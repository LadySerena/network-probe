#![deny(clippy::correctness)]
#![deny(deprecated)]
#![warn(clippy::perf)]

use axum::{routing::get, Router};
use tokio::{signal, time};

async fn app() {
    let mut interval = time::interval(time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        let body = reqwest::get("https://www.rust-lang.org")
            .await
            .unwrap()
            .text()
            .await
            .unwrap_or("can't parse body".to_string());
        println!("{body}");
    }
}

async fn health_check() -> &'static str {
    "meep"
}

#[tokio::main]
async fn main() {
    tokio::spawn(async move {
        app().await;
    });
    tokio::spawn(async move {
        let router = Router::new().route("/livez", get(health_check));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, router).await.unwrap();
    });
    signal::ctrl_c().await.unwrap();
}
