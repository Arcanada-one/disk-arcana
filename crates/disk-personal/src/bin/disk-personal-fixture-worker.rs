//! Task-owned synthetic child process. Never selected by release packaging.
#[cfg(target_os = "linux")]
mod linux {
    use disk_personal::fixture_support::{Binding, Error, Fixture, Request, Result};
    use serde::Deserialize;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Command {
        action: String,
        root: PathBuf,
        binding: Binding,
        request: Option<Request>,
        data_hex: Option<String>,
        pause_at: Option<String>,
    }

    fn decode(value: &str) -> Result<Vec<u8>> {
        if value.len() > 2 * 1_048_576 || !value.len().is_multiple_of(2) {
            return Err(Error::InvalidInput);
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).map_err(|_| Error::InvalidInput)?;
                u8::from_str_radix(text, 16).map_err(|_| Error::InvalidInput)
            })
            .collect()
    }

    pub async fn run() -> Result<()> {
        const INPUT_LIMIT: u64 = 2 * 1_048_576 + 8192;
        let mut input = Vec::new();
        std::io::stdin()
            .take(INPUT_LIMIT + 1)
            .read_to_end(&mut input)?;
        if input.len() as u64 > INPUT_LIMIT {
            return Err(Error::InvalidInput);
        }
        let command: Command = serde_json::from_slice(&input)?;
        if command.action == "initialize" {
            Fixture::initialize(&command.root, &command.binding).await?;
            println!("{{\"initialized\":true,\"scope\":\"synthetic_only\"}}");
            return Ok(());
        }
        let mut fixture = Fixture::open(&command.root, &command.binding).await?;
        if matches!(command.action.as_str(), "abandon_worker" | "cancel_close") {
            let _paused = fixture.pause_sql_worker().await?;
            if command.action == "abandon_worker" {
                drop(fixture);
            } else {
                let close = fixture.close();
                tokio::pin!(close);
                tokio::select! {
                    result = &mut close => { result?; return Err(Error::InvalidInput); },
                    () = tokio::task::yield_now() => (),
                }
                // The pinned future is dropped at this branch's end before ack.
            }
            println!("CHECKPOINT {}", command.action);
            std::io::stdout().flush()?;
            // One command/one root per child. Only process exit releases the
            // abandoned lock; no unbounded repeated orphan-worker loop exists.
            loop {
                std::thread::park();
            }
        }
        let result = match command.action.as_str() {
            "inspect" => fixture
                .inspect()
                .await
                .and_then(|value| Ok(serde_json::to_string(&value)?)),
            "stage" => {
                let request = command.request.ok_or(Error::InvalidInput)?;
                let bytes = decode(command.data_hex.as_deref().ok_or(Error::InvalidInput)?)?;
                let mut checkpoint = |name: &'static str| -> Result<()> {
                    if command.pause_at.as_deref() == Some(name) {
                        println!("CHECKPOINT {name}");
                        std::io::stdout().flush()?;
                        // Parent waits for this exact signal, then kills only this child.
                        loop {
                            std::thread::park();
                        }
                    }
                    Ok(())
                };
                fixture
                    .stage_with_checkpoint(&request, &bytes, &mut checkpoint)
                    .await
                    .and_then(|value| Ok(serde_json::to_string(&value)?))
            }
            _ => Err(Error::InvalidInput),
        };
        fixture.close().await?;
        println!("{}", result?);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = linux::run().await {
        eprintln!("synthetic fixture failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("synthetic provider requires Linux filesystem primitives");
    std::process::exit(78);
}
