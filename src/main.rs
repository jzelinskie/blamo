use actix_web::{get, middleware, web, App, HttpRequest, HttpServer};

#[get("/v2/{token}")]
async fn backdoor(_: HttpRequest, key: web::Data<String>, token: web::Path<String>) -> String {
    fernet::Fernet::new(&key)
        .unwrap()
        .encrypt(&token.into_inner().as_bytes())
}

#[get("/v1/status")]
async fn status() -> &'static str {
    "okie"
}

#[get("/v1/{token}")]
async fn v1(_: HttpRequest, key: web::Data<String>, token: web::Path<String>) -> String {
    let f = fernet::Fernet::new(&key).unwrap();
    match f.decrypt(&token.into_inner()) {
        Ok(url_vec) => String::from_utf8(url_vec).unwrap(),
        Err(_) => "nope".to_string(),
    }
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

    HttpServer::new(|| {
        App::new()
            .wrap(
                middleware::DefaultHeaders::new()
                    .header("Via", "blamo!")
                    .header("X-Frame-Options", "deny")
                    .header("X-XSS-Protection", "1; mode=block")
                    .header("X-Content-Type_options", "nosniff")
                    .header(
                        "Content-Security-Policy",
                        "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
                    ),
            )
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
            .data(fernet::Fernet::generate_key())
            .service(v1)
            .service(backdoor)
            .service(status)
    })
    .bind("127.0.0.1:8080")?
    .workers(1)
    .run()
    .await
}
