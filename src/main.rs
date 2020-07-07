use actix_web::http::header::HeaderValue;
use actix_web::{get, middleware, web, App, HttpRequest, HttpResponse, HttpServer};

use anyhow;

use fernet::Fernet;

#[get("/v1/{token}")]
async fn proxy(
    request: HttpRequest,
    key: web::Data<fernet::Fernet>,
    token: web::Path<String>,
) -> HttpResponse {
    // If the via header is from an instance of blamo, bail to avoid recursion.
    // There's definitely a way to make this more succinct.
    if let Some(via) = request.headers().get("Via") {
        if via
            .to_str()
            .expect("http headers should be strings?")
            .starts_with("blamo!")
        {
            println!("400: already via blamo!");
            return HttpResponse::BadRequest()
                .add_security_headers()
                .add_cachebust_headers()
                .finish();
        }
    };

    match key.decrypt(&token.into_inner()) {
        Ok(url_vec) => proxy_response(request, String::from_utf8(url_vec).unwrap()).await,
        Err(_) => {
            println!("400: failed to decrypt");

            HttpResponse::BadRequest()
            .add_security_headers()
            .add_cachebust_headers()
            .finish()
        }
    }
}

fn transferred_headers(request: HttpRequest) -> Vec<(String, String)> {
    vec![
        ("Via", "blamo! v0.0.1"),
        ("User-Agent", "blamo! v0.0.1"),
        (
            "Accept",
            request.headers().get_or("Accept", "image/*").as_str(),
        ),
        (
            "Accept-Encoding",
            request.headers().get_or("Accept-Encoding", "").as_str(),
        ),
        ("X-Frame-Options", "deny"),
        ("X-XSS-Protection", "1; mode=block"),
        ("X-Content-Type-Options", "nosniff"),
        (
            "Content-Security-Policy",
            "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
        ),
    ]
    .iter()
    .map(|(x, y)| (x.to_string(), y.to_string()))
    .collect()
}

trait HeaderExtensions {
    fn add_cachebust_headers(&mut self) -> &mut Self;
    fn add_security_headers(&mut self) -> &mut Self;
}

impl HeaderExtensions for actix_web::dev::HttpResponseBuilder {
    fn add_cachebust_headers(&mut self) -> &mut Self {
        self.set_header(
            "Cache-Control",
            "no-cache, no-store, private, must-revalidate",
        )
    }

    fn add_security_headers(&mut self) -> &mut Self {
        self.set_header("X-Frame-Options", "deny")
            .set_header("X-XSS-Protection", "1; mode=block")
            .set_header("X-Content-Type-Options", "nosniff")
            .set_header(
                "Content-Security-Policy",
                "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
            )
    }
}

trait GetOr {
    fn get_or(&self, header: &str, default: &str) -> String;
}

impl GetOr for actix_web::http::header::HeaderMap {
    fn get_or(&self, header: &str, default: &str) -> String {
        String::from(
            self.get(header)
                .unwrap_or(
                    &HeaderValue::from_str(default).expect("default header value should parse"),
                )
                .to_str()
                .expect("header with a default should never fail .to_str()"),
        )
    }
}

async fn proxy_response(request: HttpRequest, url: String) -> HttpResponse {
    use actix_web::http::Uri;

    let parsed_url = match url.clone().parse::<Uri>() {
        Ok(x) => x,
        Err(_) => {
            println!("400: failed to parse URL");
            return HttpResponse::BadRequest()
                .add_security_headers()
                .add_cachebust_headers()
                .finish()
        }
    };

    let scheme = match parsed_url.scheme() {
        Some(x) => x.to_string(),
        None => {
            println!("400: failed to parse scheme");
            return HttpResponse::BadRequest()
                .add_security_headers()
                .add_cachebust_headers()
                .finish()
        }
    };

    match scheme.as_str() {
        "http" => (),
        _ => {
            println!("400: scheme must be http");
            return HttpResponse::BadRequest()
                .add_security_headers()
                .add_cachebust_headers()
                .finish()
        }
    };

    let client = awc::Client::default();
    let mut proxied_request = client.get(url.as_str());
    for (k, v) in transferred_headers(request) {
        proxied_request = proxied_request.header(k.as_str(), v.as_str())
    }
    let mut response = match proxied_request.send().await {
        Ok(x) => {
            if x.status().is_success() {
                x
            } else {
                return HttpResponse::BadGateway().finish();
            }
        }
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let body = match response.body().await {
        Ok(x) => x,
        Err(_) => return HttpResponse::BadGateway().finish(),
    };


    HttpResponse::Ok()
        .header("Via", "blamo!")
        .add_security_headers()
        .set_header("Content-Type", response.headers().get_or("Content-Type", "application/octet-stream"))
        .body(body)
}

#[get("/v1/_metrics")]
async fn metrics() -> HttpResponse {
    use prometheus::{Encoder, TextEncoder};
    let mut buf = vec![];
    match TextEncoder::new().encode(&prometheus::gather(), &mut buf) {
        Ok(_) => HttpResponse::Ok().body(buf),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    let matches = clap::App::new("blamo!")
        .version("0.0.1")
        .about("securely serve trusted, insecure content")
        .author("Jimmy Zelinskie <jimmyzelinskie+git@gmail.com>")
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            clap::SubCommand::with_name("key")
                .about("key management")
                .setting(clap::AppSettings::ArgRequiredElseHelp)
                .subcommand(clap::SubCommand::with_name("generate").about("generate a new key"))
                .subcommand(
                    clap::SubCommand::with_name("encrypt")
                        .about("encrypt a message")
                        .arg(clap::Arg::with_name("key").required(true).takes_value(true))
                        .arg(
                            clap::Arg::with_name("message")
                                .required(true)
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("decrypt")
                        .about("decrypt ciphertext")
                        .arg(clap::Arg::with_name("key").required(true).takes_value(true))
                        .arg(
                            clap::Arg::with_name("ciphertext")
                                .required(true)
                                .takes_value(true),
                        ),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("server")
                .about("http proxy server")
                .setting(clap::AppSettings::ArgRequiredElseHelp)
                .subcommand(
                    clap::SubCommand::with_name("run")
                        .about("run the server")
                        .setting(clap::AppSettings::ArgRequiredElseHelp)
                        .args(&[
                            clap::Arg::with_name("key")
                                .required(true)
                                .takes_value(true)
                                .help("key used to decrypt URLs"),
                            clap::Arg::with_name("port")
                                .short("p")
                                .long("port")
                                .takes_value(true)
                                .default_value("8080")
                                .help("port bound to serve HTTP requests"),
                        ]),
                ),
        )
        .get_matches();

    let invalid_key = anyhow::anyhow!("invalid key");
    if let Some(matches) = matches.subcommand_matches("key") {
        if let Some(_) = matches.subcommand_matches("generate") {
            println!("{}", fernet::Fernet::generate_key());
            return Ok(());
        }

        if let Some(matches) = matches.subcommand_matches("encrypt") {
            let key = Fernet::new(matches.value_of("key").expect("key requires a value"))
                .ok_or_else(|| invalid_key)?;
            let message = matches
                .value_of("message")
                .expect("message requires a value");
            println!("{}", key.encrypt(message.as_bytes()));
            return Ok(());
        }

        if let Some(matches) = matches.subcommand_matches("decrypt") {
            let key = Fernet::new(matches.value_of("key").expect("key requires a value"))
                .ok_or_else(|| invalid_key)?;
            let ciphertext = matches
                .value_of("ciphertext")
                .expect("ciphertext requires a value");
            let decrypted_message = key
                .decrypt(ciphertext)
                .map_err(|_| anyhow::anyhow!("failed to decrypt ciphertext"))?;
            println!("{}", String::from_utf8(decrypted_message)?);
            return Ok(());
        }
    }

    if let Some(matches) = matches.subcommand_matches("server") {
        if let Some(matches) = matches.subcommand_matches("run") {
            let key_str = matches
                .value_of("key")
                .expect("key requires a value")
                .to_owned();

            // Ensure the key is valid before trying to handle any requests.
            Fernet::new(&key_str).ok_or_else(|| invalid_key)?;

            println!("listening on localhost:8080...");
            return HttpServer::new(move || {
                let key = fernet::Fernet::new(&key_str.clone())
                    .expect("key has been previously validated");
                App::new()
                    .wrap(middleware::Compress::default())
                    .wrap(middleware::Logger::default())
                    .service(
                        web::resource("/v1/_healthy").route(web::get().to(|| HttpResponse::Ok())),
                    )
                    .service(
                        web::resource("/v1/_ready").route(web::get().to(|| HttpResponse::Ok())),
                    )
                    .service(metrics)
                    .data(key)
                    .service(proxy)
            })
            .bind("127.0.0.1:8080")?
            .workers(1)
            .run()
            .await
            .map_err(From::from);
        }
    }
    unreachable!()
}
