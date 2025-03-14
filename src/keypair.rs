///! Brought from solana-sdk to add the necessary function
use ed25519_dalek::Signer as DalekSigner;
use rand::{CryptoRng, RngCore, rngs::OsRng};
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{Signer, SignerError},
};

/// A vanilla Ed25519 key pair
#[derive(Debug)]
pub struct Keypair(ed25519_dalek::Keypair);

impl Keypair {
    /// Can be used for generating a Keypair without a dependency on `rand` types
    pub const SECRET_KEY_LENGTH: usize = 32;

    /// Constructs a new, random `Keypair` using a caller-provided RNG
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(ed25519_dalek::Keypair::generate(csprng))
    }

    /// Constructs a new, random `Keypair` using `OsRng`
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self::generate(&mut rng)
    }

    /// Recovers a `Keypair` from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        if bytes.len() < ed25519_dalek::KEYPAIR_LENGTH {
            return Err(ed25519_dalek::SignatureError::from_source(String::from(
                "candidate keypair byte array is too short",
            )));
        }
        let secret =
            ed25519_dalek::SecretKey::from_bytes(&bytes[..ed25519_dalek::SECRET_KEY_LENGTH])?;
        let public =
            ed25519_dalek::PublicKey::from_bytes(&bytes[ed25519_dalek::SECRET_KEY_LENGTH..])?;
        let expected_public = ed25519_dalek::PublicKey::from(&secret);
        (public == expected_public)
            .then_some(Self(ed25519_dalek::Keypair { secret, public }))
            .ok_or(ed25519_dalek::SignatureError::from_source(String::from(
                "keypair bytes do not specify same pubkey as derived from their secret key",
            )))
    }

    /// Returns this `Keypair` as a byte array
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Recovers a `Keypair` from a base58-encoded string
    pub fn from_base58_string(s: &str) -> Self {
        let mut buf = [0u8; ed25519_dalek::KEYPAIR_LENGTH];
        bs58::decode(s).onto(&mut buf).unwrap();
        Self::from_bytes(&buf).unwrap()
    }

    /// Returns this `Keypair` as a base58-encoded string
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.0.to_bytes()).into_string()
    }

    /// Gets this `Keypair`'s SecretKey
    pub fn secret(&self) -> &ed25519_dalek::SecretKey {
        &self.0.secret
    }

    /// Allows Keypair cloning
    ///
    /// Note that the `Clone` trait is intentionally unimplemented because making a
    /// second copy of sensitive secret keys in memory is usually a bad idea.
    ///
    /// Only use this in tests or when strictly required. Consider using [`std::sync::Arc<Keypair>`]
    /// instead.
    pub fn insecure_clone(&self) -> Self {
        Self(ed25519_dalek::Keypair {
            // This will never error since self is a valid keypair
            secret: ed25519_dalek::SecretKey::from_bytes(self.0.secret.as_bytes()).unwrap(),
            public: self.0.public,
        })
    }

    pub fn sign_message_with_index(&self, message: &[u8], index: u8) -> Signature {
        Signature::from(
            self.0
                .try_sign_with_index(message, index)
                .expect("signature operation failed")
                .to_bytes(),
        )
    }
}

impl From<ed25519_dalek::Keypair> for Keypair {
    fn from(value: ed25519_dalek::Keypair) -> Self {
        Self(value)
    }
}

impl Signer for Keypair {
    #[inline]
    fn pubkey(&self) -> Pubkey {
        Pubkey::from(self.0.public.to_bytes())
    }

    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey())
    }

    fn sign_message(&self, message: &[u8]) -> Signature {
        Signature::from(self.0.sign(message).to_bytes())
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.sign_message(message))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}
