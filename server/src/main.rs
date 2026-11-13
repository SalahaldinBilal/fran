use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match fran_sync_server::cli::run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
