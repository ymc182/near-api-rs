use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::{from_str, json, Value};
pub struct Near {
    pub rpc_url: String,
}

#[derive(Deserialize, Debug)]
pub struct AccountState {
    pub amount: f64,
    pub storage_usage: u64,
    pub code_hash: String,
    pub storage_paid_at: u64,
    pub block_height: u64,
}

#[derive(Deserialize, Debug)]
pub struct KeyPair {
    pub public_key: String,
    pub secret_key: String,
    pub signing_key: [u8; 32],
    pub verifying_key: [u8; 32],
}

impl KeyPair {
    pub fn account_id(&self) -> String {
        //from bs58 to hex string
        let public_key_bytes = bs58::decode(&self.public_key).into_vec().unwrap();
        let account_id = hex::encode(&public_key_bytes);
        account_id
    }
    pub fn from_random() -> KeyPair {
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

    pub fn from_string(secret_key: String) -> KeyPair {
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
}

impl Near {
    pub async fn view_account(
        &self,
        account_id: String,
    ) -> Result<AccountState, Box<dyn std::error::Error>> {
        let url = format!("{}", self.rpc_url);
        let body_json = json!({
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "query",
            "params": {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id
            }
        })
        .to_string();

        let body = reqwest::Client::new()
            .post(&url)
            .body(body_json)
            .header("Content-Type", "application/json")
            .send()
            .await?
            .text()
            .await?;

        let res: Value = from_str(&body).unwrap();
        println!("{:?}", res);
        let account: AccountState = AccountState {
            amount: res["result"]["amount"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap()
                / (10u128.pow(24) as f64),
            storage_usage: res["result"]["storage_usage"].as_u64().unwrap(),

            code_hash: res["result"]["code_hash"].as_str().unwrap().to_string(),
            storage_paid_at: res["result"]["storage_paid_at"].as_u64().unwrap(),

            block_height: res["result"]["block_height"].as_u64().unwrap(),
        };

        Ok(account)
    }
}

#[tokio::main]
async fn main() {
    let near = Near {
        rpc_url: "https://rpc.mainnet.near.org".to_string(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_id() {
        let new_key_pair = KeyPair::from_random();
        let account_id = new_key_pair.account_id();
        let sk = new_key_pair.secret_key;

        let test_key_pair = KeyPair::from_string(sk);
        let test_account_id = test_key_pair.account_id();

        assert_eq!(account_id, test_account_id);
    }
}
