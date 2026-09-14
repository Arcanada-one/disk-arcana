use std::process::Command;

#[test]
fn production_entry_refuses_even_with_enable_environment_and_arguments() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("must-not-be-created");
    let output = Command::new(env!("CARGO_BIN_EXE_disk-arcana-personal"))
        .env("PERSONAL_RUNTIME_ENABLED", "1")
        .env("PERSONAL_ROOT", &missing)
        .env("DATABASE_URL", "sqlite:must-not-open.sqlite")
        .args(["--serve", "--root"])
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "personal runtime not integrated"
    );
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    // This test proves refusal/no mutation only. An external strace probe
    // separately measures the absence of private-root opens and socket binds.
}
