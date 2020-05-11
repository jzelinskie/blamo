use actix_web::{get, middleware, web, App, HttpRequest, HttpResponse, HttpServer};

use actix_web::http::header::HeaderValue;
use fernet::Fernet;

#[get("/v2/{token}")]
async fn backdoor(key: web::Data<String>, token: web::Path<String>) -> HttpResponse {
    let f = match fernet::Fernet::new(&key) {
        Some(x) => x,
        None => return HttpResponse::InternalServerError().finish(),
    };

    let mut schemed_token = "https://".to_owned();
    schemed_token.push_str(&token.into_inner());

    HttpResponse::Ok().body(f.encrypt(&schemed_token.as_bytes()))
}

#[get("/v1/{token}")]
async fn proxy(
    request: HttpRequest,
    key: web::Data<String>,
    token: web::Path<String>,
) -> HttpResponse {
    let f = match fernet::Fernet::new(&key) {
        Some(x) => x,
        None => return HttpResponse::InternalServerError().finish(),
    };

    match f.decrypt(&token.into_inner()) {
        Ok(url_vec) => proxy_response(request, String::from_utf8(url_vec).unwrap()),
        Err(_) => HttpResponse::BadRequest().finish(),
    }
}

fn transferred_headers(request: HttpRequest) -> Vec<(String, String)> {
    vec![
        ("Via", "hello"),
        ("User-Agent", "hello"),
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

trait GetOr {
    fn get_or(&self, header: &str, default: &str) -> String;
}

impl GetOr for actix_web::http::header::HeaderMap {
    fn get_or(&self, header: &str, default: &str) -> String {
        String::from(
            self.get(header)
                .unwrap_or(&HeaderValue::from_str(default).unwrap())
                .to_str()
                .unwrap(),
        )
    }
}

fn proxy_response(request: HttpRequest, url: String) -> HttpResponse {
    use actix_web::http::Uri;

    let parsed_url = match url.clone().parse::<Uri>() {
        Ok(x) => x,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };

    let scheme = match parsed_url.scheme() {
        Some(x) => x.to_string(),
        None => return HttpResponse::BadRequest().finish(),
    };

    match scheme.as_str() {
        "http" => (),
        _ => return HttpResponse::BadRequest().finish(),
    };

    HttpResponse::Ok()
        .header("Via", "blamo!")
        .header("X-Frame-Options", "deny")
        .header("X-XSS-Protection", "1; mode=block")
        .header("X-Content-Type_options", "nosniff")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
        )
        .body(scheme)
}

#[get("/v1/_metrics")]
async fn metrics() -> HttpResponse {
    use prometheus::{Encoder, TextEncoder};

    let mut buf = vec![];
    TextEncoder::new()
        .encode(&prometheus::gather(), &mut buf)
        .unwrap();

    HttpResponse::Ok().body(buf)
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    /*
    let client = awc::Client::new();

    let mut response = client
        .get("https://rust-lang.org")
        .header("User-Agent", "actix-web")
        .send()
        .await?;
    println!("Response: {:?}", response);

    let body = response.body().await?;
    println!("Downloaded: {:?} bytes", body.len());
    */

    let matches = clap::App::new("blamo!")
        .version("0.0.1")
        .about("securely serve trusted, insecure content")
        .author("Jimmy Zelinskie <jimmyzelinskie+git@gmail.com>")
        .subcommand(
            clap::SubCommand::with_name("key")
                .about("key management")
                .setting(clap::AppSettings::ArgRequiredElseHelp)
                .subcommand(clap::SubCommand::with_name("generate").about("generate a new key"))
                .subcommand(
                    clap::SubCommand::with_name("encrypt")
                        .about("encrypt a message")
                        .arg(
                            clap::Arg::with_name("key")
                                .required(true)
                                .takes_value(true)
                        )
                        .arg(
                            clap::Arg::with_name("message")
                                .required(true)
                                .takes_value(true)
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("decrypt")
                        .about("decrypt a message")
                        .arg(
                            clap::Arg::with_name("key")
                                .required(true)
                                .takes_value(true)
                        )
                        .arg(
                            clap::Arg::with_name("message")
                                .required(true)
                                .takes_value(true)
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
                        .arg(
                            clap::Arg::with_name("key")
                                .required(true)
                                .takes_value(true)
                                .help("key used to decrypt URLs"),
                        ),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("key") {
        if let Some(_) = matches.subcommand_matches("generate") {
            println!("{}", fernet::Fernet::generate_key());
            return Ok(());
        }

        if let Some(matches) = matches.subcommand_matches("encrypt") {
            let key = match Fernet::new(matches.value_of("key").unwrap()) {
                Some(x) => x,
                None => return Ok(()), // TODO(jzelinskie): exit 1
            };

            let message = matches.value_of("message").unwrap();
            println!("{}", key.encrypt(message.as_bytes()));

            return Ok(());
        }

        if let Some(matches) = matches.subcommand_matches("decrypt") {
            let key = match Fernet::new(matches.value_of("key").unwrap()) {
                Some(x) => x,
                None => return Ok(()), // TODO(jzelinskie): exit 1
            };

            let message = matches.value_of("message").unwrap();
            let decrypted_message = match key.decrypt(message) {
                Ok(x) => x,
                Err(_) => return Ok(()), // TODO(jzelinskie) exit 1
            };

            println!("{}", String::from_utf8(decrypted_message).unwrap());

            return Ok(());
        }
    }

    if let Some(matches) = matches.subcommand_matches("server") {
        if let Some(matches) = matches.subcommand_matches("run") {
            let key = matches.value_of("key").unwrap().to_owned();
            println!("running server with key: {}", &key);
            return HttpServer::new(move || {
                let key = key.clone();
                App::new()
                    .wrap(middleware::Compress::default())
                    .wrap(middleware::Logger::default())
                    .data(key)
                    .service(metrics)
                    .service(backdoor)
                    .service(proxy)
            })
            .bind("127.0.0.1:8080")?
            .workers(1)
            .run()
            .await;
        }
    }
    unreachable!()
}
