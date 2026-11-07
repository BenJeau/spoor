use std::fs::File;
use tracing::info;

mod log_list;
mod rfc6962;
mod tiled;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let data = log_list::LogList::get().await.unwrap();
    info!("Parsed {} operators", data.operators.len());

    let file = File::create("log_list.json").unwrap();
    serde_json::to_writer_pretty(file, &data);
}
