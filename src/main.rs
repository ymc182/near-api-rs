use serde::Deserialize;
use serde_json::{from_str, json, Value};
mod key_pair;
#[derive(Deserialize, Debug)]
pub struct AccountState {
    pub amount: f64,
    pub storage_usage: u64,
    pub code_hash: String,
    pub storage_paid_at: u64,
    pub block_height: u64,
}

pub struct Near {
    pub rpc_url: String,
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

    use base64::Engine;
    use ed25519_dalek::Signature;
    use ed25519_dalek::Verifier;
    use ed25519_dalek::VerifyingKey;
    use key_pair::KeyPair;
    use key_pair::KeyPairTrait;
    #[test]
    fn test_account_id() {
        let new_key_pair = KeyPair::from_random();
        let account_id = new_key_pair.account_id();
        let sk = new_key_pair.secret_key;

        let test_key_pair = KeyPair::from_string(sk);
        let test_account_id = test_key_pair.account_id();

        assert_eq!(account_id, test_account_id);
    }

    #[test]
    fn sign_and_verify_message() {
        let new_key_pair = KeyPair::from_random();
        let verify_key = VerifyingKey::from_bytes(&new_key_pair.verifying_key).unwrap();
        let message = "hello world".to_string();
        let signature = new_key_pair.sign_message(message.clone());

        //Verify
        let decoded_signature: [u8; 64] = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(signature.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let received_signature = Signature::from_bytes(&decoded_signature);
        let is_valid = verify_key
            .verify(&message.as_bytes(), &received_signature)
            .is_ok();

        let failed_signature = Signature::from_bytes(&[0u8; 64]);
        let is_invalid = verify_key
            .verify(&message.as_bytes(), &failed_signature)
            .is_ok();

        assert_eq!(is_valid, true);
        assert_eq!(is_invalid, false);
    }
}
