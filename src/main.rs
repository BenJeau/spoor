mod cli;
mod log_list;
mod rfc6962;
mod tiled;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    cli::launch_cli().await
}
