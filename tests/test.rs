use rrr_make::registry::OwnedRegistry;
use tempfile::tempdir;
use tracing_test::traced_test;

#[tokio::test]
#[traced_test]
async fn owned_registry() {
    let registry_dir = tempdir().unwrap();

    dbg!(&registry_dir);

    let owned_registry = OwnedRegistry::generate(registry_dir.path(), false)
        .await
        .unwrap()
        .lock_read()
        .await
        .unwrap();
    let owned_registry_loaded = OwnedRegistry::load(registry_dir.path()).await.unwrap();

    assert_eq!(owned_registry_loaded, owned_registry);

    let root_record = owned_registry_loaded.load_root_record().await.unwrap();

    assert_eq!(root_record.successive_records.len(), 2);
    assert!(root_record.successive_records[0]
        .successive_records
        .is_empty());
}

#[cfg(feature = "cmd")]
#[tokio::test]
#[traced_test]
async fn new_registry() {
    use rrr_make::cmd::Command;

    let registry_dir = tempdir().unwrap();
    Command::New {
        directory: registry_dir.path().into(),
        force: false,
    }
    .process()
    .await
    .unwrap();
    Command::Make {
        input_directory: registry_dir.path().into(),
        publish: false,
        force: false,
    }
    .process()
    .await
    .unwrap();
}
