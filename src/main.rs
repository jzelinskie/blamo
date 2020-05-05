use actix_web::{get, middleware, post, web, App, HttpRequest, HttpServer};
use serde::Deserialize;

#[derive(Deserialize)]
struct UrlQuery {
    path: String,
}

#[post("/v1/urls")]
async fn urls(r: HttpRequest, q: web::Query<UrlQuery>) -> String {
    println!("REQ: {:?}", r);
    format!("I should be hmacing: {}!\r\n", q.path)
}

#[get("/v1/contents/{token}")]
async fn contents(r: HttpRequest, token: web::Path<String>) -> String {
    println!("REQ: {:?}", r);
    format!("I should be showing: {}!\r\n", token)
}

#[get("/v1/status")]
async fn status() -> &'static str {
    "okie"
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
            .service(urls)
            .service(contents)
            .service(status)
    })
    .bind("127.0.0.1:8080")?
    .workers(1)
    .run()
    .await
}
