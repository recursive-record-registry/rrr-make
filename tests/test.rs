use std::path::PathBuf;

use rrr::{
    crypto::{
        encryption::EncryptionAlgorithm,
        kdf::{hkdf::HkdfParams, KdfAlgorithm},
        password_hash::{argon2::Argon2Params, PasswordHashAlgorithm},
    },
    registry::{RegistryConfigHash, RegistryConfigKdf},
};
use rrr_make::{
    record::{OwnedRecordConfigEncryption, OwnedRecordConfigParameters, SplittingStrategy},
    registry::{OwnedRegistry, OwnedRegistryConfig},
};
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

#[tokio::test]
#[traced_test]
async fn new_registry_config() {
    let registry_dir = tempdir().unwrap();

    dbg!(&registry_dir);

    let generated_registry = OwnedRegistry::generate(registry_dir.path(), false)
        .await
        .unwrap()
        .lock_read()
        .await
        .unwrap();
    let generated_config = &generated_registry.config;
    let expected_config = OwnedRegistryConfig {
        hash: RegistryConfigHash {
            algorithm: PasswordHashAlgorithm::Argon2(Argon2Params::default()),
            output_length_in_bytes: Default::default(),
        },
        kdf: RegistryConfigKdf::builder()
            .with_algorithm(KdfAlgorithm::Hkdf(HkdfParams::default()))
            .build(
                generated_config
                    .kdf
                    .get_root_record_predecessor_nonce()
                    .clone(),
            )
            .unwrap(),
        default_record_parameters: OwnedRecordConfigParameters {
            splitting_strategy: SplittingStrategy::Fill {},
            encryption: Some(OwnedRecordConfigEncryption {
                algorithm: EncryptionAlgorithm::Aes256Gcm,
                segment_padding_to_bytes: 1024, // 1 KiB
            }),
        }
        .into(),
        staging_directory_path: PathBuf::from("target/staging"),
        revisions_directory_path: PathBuf::from("target/revisions"),
        published_directory_path: PathBuf::from("target/published"),
        root_record_path: PathBuf::from("root"),
        signing_key_paths: vec![PathBuf::from("keys/key_ed25519.pem")],
    };

    println!(
        "\ngenerated config:\n{}",
        toml::to_string_pretty(generated_config).unwrap()
    );
    println!(
        "\nexpected config:\n{}",
        toml::to_string_pretty(&expected_config).unwrap()
    );

    assert_eq!(generated_config, &expected_config);
}

#[cfg(feature = "cmd")]
#[tokio::test]
#[traced_test]
async fn commands_new_make() {
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
