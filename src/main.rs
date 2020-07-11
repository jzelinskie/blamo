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
    if request
        .headers()
        .get("Via")
        .and_then(|x| x.to_str().ok())
        .map_or(false, |x| x.starts_with("blamo!"))
    {
        println!("400: already via blamo!");
        return HttpResponse::BadRequest().as_blamo_error();
    };

    match key.decrypt(&token.into_inner()) {
        Ok(url_vec) => {
            match String::from_utf8(url_vec) {
                Ok(url) => proxy_response(request, url).await,
                Err(_) => {
                    println!("400: failed to parse encrypted URL");
                    HttpResponse::BadRequest().as_blamo_error()
                }
            }
        }
        Err(_) => {
            println!("400: failed to decrypt");
            HttpResponse::BadRequest().as_blamo_error()
        }
    }
}

trait ResponseHeaderExtensions {
    fn as_blamo_error(&mut self) -> HttpResponse;
    fn add_default_headers(&mut self) -> &mut Self;
    fn add_cachebust_headers(&mut self) -> &mut Self;
    fn transfer_response_headers(&mut self, headers: &awc::http::header::HeaderMap) -> &mut Self;
    fn add_security_headers(&mut self) -> &mut Self;
}

impl ResponseHeaderExtensions for actix_web::dev::HttpResponseBuilder {
    fn as_blamo_error(&mut self) -> HttpResponse {
        self.add_default_headers().add_cachebust_headers().finish()
    }

    fn add_default_headers(&mut self) -> &mut Self {
        self.header("Via", "blamo!")
            .header("Server", "blamo! v0.0.1")
    }

    fn add_cachebust_headers(&mut self) -> &mut Self {
        self.header(
            "Cache-Control",
            "no-cache, no-store, private, must-revalidate",
        )
    }

    fn transfer_response_headers(&mut self, headers: &awc::http::header::HeaderMap) -> &mut Self {
        // Add these headers with defaults.
        self.content_type(
            headers
                .get("Content-Type")
                .cloned()
                .unwrap_or(HeaderValue::from_static("application/octet-stream")),
        )
        .header(
            "Cache-Control",
            headers
                .get("Cache-Control")
                .cloned()
                .unwrap_or(HeaderValue::from_static("public, max-age=31536000")),
        );

        // Add these headers only if they appear in the response.
        [
            "ETag",
            "Expires",
            "Last-Modified",
            "Content-Length",
            "Transfer-Encoding",
            "Content-Encoding",
        ]
        .iter()
        .for_each(|&header| {
            match headers.get(header).cloned() {
                Some(value) => {
                    self.header(header, value);
                }
                None => (),
            };
        });

        self
    }

    fn add_security_headers(&mut self) -> &mut Self {
        self.header("X-Frame-Options", "deny")
            .header("X-XSS-Protection", "1; mode=block")
            .header("X-Content-Type-Options", "nosniff")
            .header(
                "Content-Security-Policy",
                "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
            )
    }
}

trait RequestHeaderExtensions {
    fn transfer_request_headers(self, headers: &actix_web::http::header::HeaderMap) -> Self;
}

impl RequestHeaderExtensions for awc::ClientRequest {
    fn transfer_request_headers(self, headers: &actix_web::http::header::HeaderMap) -> Self {
        self.header(
            "User-Agent",
            headers
                .get("User-Agent")
                .cloned()
                .unwrap_or(HeaderValue::from_static("blamo! v0.0.1")),
        )
        .header(
            "Accept",
            headers
                .get("Accept")
                .cloned()
                .unwrap_or(HeaderValue::from_static("image/*")),
        )
        .header(
            "Accept-Encoding",
            headers
                .get("Accept-Encoding")
                .cloned()
                .unwrap_or(HeaderValue::from_static("*")),
        )
    }
}

async fn proxy_response(request: HttpRequest, url: String) -> HttpResponse {
    use actix_web::http::Uri;

    let parsed_url = match url.clone().parse::<Uri>() {
        Ok(x) => x,
        Err(_) => {
            println!("400: failed to parse URL");
            return HttpResponse::BadRequest().as_blamo_error();
        }
    };

    let scheme = match parsed_url.scheme() {
        Some(x) => x,
        None => {
            println!("400: failed to parse scheme");
            return HttpResponse::BadRequest().as_blamo_error();
        }
    };

    match scheme.as_str() {
        "http" => (),
        _ => {
            println!("400: scheme must be http");
            return HttpResponse::BadRequest().as_blamo_error();
        }
    };

    let client = awc::Client::default();
    let mut response = match client
        .get(url.as_str())
        .transfer_request_headers(request.headers())
        .send()
        .await
    {
        Ok(x) => {
            if x.status().is_success() {
                x
            } else {
                println!("502: upstream response non-200");
                return HttpResponse::BadGateway().as_blamo_error();
            }
        }
        Err(_) => {
            println!("502: failure receiving upstream response");
            return HttpResponse::BadGateway().as_blamo_error();
        }
    };

    let body = match response.body().await {
        Ok(x) => x,
        Err(_) => {
            println!("502: failure receiving upstream body");
            return HttpResponse::BadGateway().as_blamo_error();
        }
    };

    println!("200: proxied {}", url);
    HttpResponse::Ok()
        .add_default_headers()
        .add_security_headers()
        .transfer_response_headers(&response.headers())
        .body(body)
}

#[get("/v1/_metrics")]
async fn metrics() -> HttpResponse {
    use prometheus::{Encoder, TextEncoder};
    let mut buf = vec![];
    match TextEncoder::new().encode(&prometheus::gather(), &mut buf) {
        Ok(_) => HttpResponse::Ok().body(buf),
        Err(_) => HttpResponse::InternalServerError().as_blamo_error(),
    }
}

fn parse_args<'a>() -> clap::ArgMatches<'a> {
    return clap::App::new("blamo!")
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
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    let matches = parse_args();
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
