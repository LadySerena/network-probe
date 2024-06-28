#![deny(clippy::correctness)]
#![deny(deprecated)]
#![warn(clippy::perf)]

use tokio::{signal, time};

async fn app() {
    let mut interval = time::interval(time::Duration::from_secs(5));
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

#[tokio::main]
async fn main() {
    tokio::spawn(async move {
        app().await;
    });
    signal::ctrl_c().await.unwrap();
}
