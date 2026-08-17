//! `kairox init` — write a safe starter config file. Never generates
//! wallets, private keys, or API key values; never overwrites an existing
//! file without `--force`.

use crate::cli::args::InitArgs;
use crate::config::{conventional_config_path, default_config_toml};
use crate::execution::errors::{KairoxError, SessionError};

pub fn run(args: InitArgs) -> Result<(), KairoxError> {
    let path = match args.path {
        Some(p) => p,
        None => conventional_config_path().ok_or_else(|| {
            KairoxError::Session(SessionError(
                "could not determine a conventional config path (neither HOME nor USERPROFILE is set); pass --path explicitly".into(),
            ))
        })?,
    };

    if path.exists() && !args.force {
        return Err(KairoxError::Session(SessionError(format!(
            "{} already exists; pass --force to overwrite it",
            path.display()
        ))));
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            KairoxError::Session(SessionError(format!(
                "failed to create directory {}: {e}",
                parent.display()
            )))
        })?;
    }

    std::fs::write(&path, default_config_toml()).map_err(|e| {
        KairoxError::Session(SessionError(format!(
            "failed to write {}: {e}",
            path.display()
        )))
    })?;

    println!("Wrote starter config to {}", path.display());
    println!(
        "Edit it to reference your own RPC/OpenSea environment variable names -- never paste a secret value into it."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_parseable_starter_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let args = InitArgs {
            path: Some(path.clone()),
            force: false,
        };
        run(args).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let parsed: crate::config::KairoxConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.version, crate::config::CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "pre-existing content").unwrap();
        let args = InitArgs {
            path: Some(path.clone()),
            force: false,
        };
        let err = run(args).unwrap_err();
        assert!(matches!(err, KairoxError::Session(_)));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "pre-existing content"
        );
    }

    #[test]
    fn force_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "pre-existing content").unwrap();
        let args = InitArgs {
            path: Some(path.clone()),
            force: true,
        };
        run(args).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_ne!(text, "pre-existing content");
    }
}
