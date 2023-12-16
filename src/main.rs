use ed25519_dalek::{SecretKey, Signature, VerifyingKey};
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

        let secret_key_str = bs58::encode(secret_key_bytes);
        let public_key_str = bs58::encode(public_key_bytes);

        KeyPair {
            public_key: public_key_str.into_string(),
            secret_key: secret_key_str.into_string(),
            signing_key: secret_key_bytes,
            verifying_key: public_key_bytes,
        }
    }

    pub fn from_string(secret_key: String) -> KeyPair {
        let secret_key_bytes: [u8; 32] = bs58::decode(&secret_key)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let secret_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_bytes);

        let public_key = secret_key.verifying_key();

        let secret_key_bytes = secret_key.to_bytes();
        let public_key_bytes = public_key.to_bytes();

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

    let new_key = KeyPair::from_random();

    println!("{:?}", new_key);
    println!("Account Id:{}", new_key.account_id());

    let key = KeyPair::from_string("Fm1eZbaftdmnT2dMjhHnXi7w9L7ppD44ubRuYuc6AVH7".to_string());

    println!("{:?}", key);
    //Id:fed9f401e2b82d2ddad4c1542b42009dafaf4d25e5a055c0cc077ac0c1d6539c
    println!("Account Id:{}", key.account_id());
    let account_id = "ewtd.near".to_string();
    let account = near.view_account(account_id).await.unwrap();
    println!("{:?}", account);
}
