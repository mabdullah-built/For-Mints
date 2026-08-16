#[tokio::main]
async fn main() {
    let code = kairox::cli::run().await;
    std::process::exit(code);
}
