use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use serde::Deserialize;
#[derive(Deserialize, Debug)]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
    pub signing_key: [u8; 32],
    pub verifying_key: [u8; 32],
}

pub trait KeyPairTrait {
    fn account_id(&self) -> String;
    fn from_random() -> KeyPair;
    fn from_string(secret_key: String) -> KeyPair;
    fn sign_message(&self, message: String) -> String;
}

impl KeyPairTrait for KeyPair {
    fn account_id(&self) -> String {
        //from bs58 to hex string
        let public_key_bytes = bs58::decode(&self.public_key).into_vec().unwrap();
        let account_id = hex::encode(&public_key_bytes);
        account_id
    }
    fn from_random() -> KeyPair {
        let mut csprng = OsRng;
        let secret_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let public_key = secret_key.verifying_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();
        let combined_key = [&secret_key_bytes[..], &public_key_bytes[..]].concat();
        let public_key_str = bs58::encode(public_key_bytes);
        let combined_key_str = bs58::encode(combined_key);

        KeyPair {
            public_key: public_key_str.into_string(),
            secret_key: combined_key_str.into_string(),

            signing_key: secret_key_bytes,
            verifying_key: public_key_bytes,
        }
    }

    fn from_string(secret_key: String) -> KeyPair {
        let combined_key_bytes: [u8; 64] = bs58::decode(&secret_key)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();

        let secret_key_bytes: [u8; 32] = combined_key_bytes[..32].try_into().unwrap();
        let public_key_bytes: [u8; 32] = combined_key_bytes[32..].try_into().unwrap();

        let secret_key_str = bs58::encode(secret_key_bytes);
        let public_key_str = bs58::encode(public_key_bytes);

        KeyPair {
            public_key: public_key_str.into_string(),
            secret_key: secret_key_str.into_string(),
            signing_key: secret_key_bytes,
            verifying_key: public_key_bytes,
        }
    }

    fn sign_message(&self, message: String) -> String {
        let secret_key_bytes = self.signing_key;
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_bytes);
        let message_bytes = message.as_bytes();
        let signature = secret_key.sign(message_bytes);
        //base64 encode
        let signature_str = general_purpose::STANDARD_NO_PAD.encode(signature.to_bytes());
        signature_str
    }
}
