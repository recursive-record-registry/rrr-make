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
        .unwrap();
    let owned_registry_loaded = OwnedRegistry::load(registry_dir.path()).await.unwrap();

    assert_eq!(owned_registry_loaded, owned_registry);
}
