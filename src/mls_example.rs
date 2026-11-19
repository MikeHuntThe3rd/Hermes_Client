use openmls::{prelude::{*,  tls_codec::*}};
use openmls_rust_crypto::{OpenMlsRustCrypto};
use openmls_basic_credential::SignatureKeyPair;

// Define ciphersuite ...
let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// ... and providers for both parties to use.
let sasha_provider = &OpenMlsRustCrypto::default();
let maxim_provider = &OpenMlsRustCrypto::default();

// Now let's create two participants.

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm)
            .expect("Error generating a signature key pair.");

    // Store the signature key into the key store so OpenMLS has access
    // to it.
    signature_keys
        .store(provider.storage())
        .expect("Error storing signature keys in key store.");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// A helper to create key package bundles.
fn generate_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
    // Create the key package
    KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            signer,
            credential_with_key,
        )
        .unwrap()
}

// First they need credentials to identify them
let (sasha_credential_with_key, sasha_signer) = generate_credential_with_key(
    "Sasha".into(),
    CredentialType::Basic,
    ciphersuite.signature_algorithm(),
    sasha_provider,
);

let (maxim_credential_with_key, maxim_signer) = generate_credential_with_key(
    "Maxim".into(),
    CredentialType::Basic,
    ciphersuite.signature_algorithm(),
    maxim_provider,
);

// Then they generate key packages to facilitate the asynchronous handshakes
// in MLS

// Generate KeyPackages
let maxim_key_package = generate_key_package(ciphersuite, maxim_provider, &maxim_signer, maxim_credential_with_key);

// Now Sasha starts a new group ...
let mut sasha_group = MlsGroup::new(
    sasha_provider,
    &sasha_signer,
    &MlsGroupCreateConfig::default(),
    sasha_credential_with_key,
)
.expect("An unexpected error occurred.");

// ... and invites Maxim.
// The key package has to be retrieved from Maxim in some way. Most likely
// via a server storing key packages for users.
let (mls_message_out, welcome_out, group_info) = sasha_group
    .add_members(sasha_provider, &sasha_signer, core::slice::from_ref(maxim_key_package.key_package()))
    .expect("Could not add members.");

// Sasha merges the pending commit that adds Maxim.
sasha_group
   .merge_pending_commit(sasha_provider)
   .expect("error merging pending commit");

// Sasha serializes the [`MlsMessageOut`] containing the [`Welcome`].
let serialized_welcome = welcome_out
   .tls_serialize_detached()
   .expect("Error serializing welcome");

// Maxim can now de-serialize the message as an [`MlsMessageIn`] ...
let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
   .expect("An unexpected error occurred.");

// ... and inspect the message.
let welcome = match mls_message_in.extract() {
   MlsMessageBodyIn::Welcome(welcome) => welcome,
   // We know it's a welcome message, so we ignore all other cases.
   _ => unreachable!("Unexpected message type."),
};

// Now Maxim can build a staged join for the group in order to inspect the welcome
let maxim_staged_join = StagedWelcome::new_from_welcome(
    maxim_provider,
    &MlsGroupJoinConfig::default(),
    welcome,
    // The public tree is needed and transferred out of band.
    // It is also possible to use the [`RatchetTreeExtension`]
    Some(sasha_group.export_ratchet_tree().into()),
)
.expect("Error creating a staged join from Welcome");

// Finally, Maxim can create the group
let mut maxim_group = maxim_staged_join
    .into_group(maxim_provider)
    .expect("Error creating the group from the staged join");
