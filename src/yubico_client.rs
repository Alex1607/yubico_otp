use crate::response_state::State;
use derive_builder::Builder;
use rand::distributions::{Alphanumeric, DistString};
use reqwest::Client;
use serde::Serialize;
use std::str::FromStr;

const YUBICO_API_URL: &str = "https://api.yubico.com/wsapi/2.0/verify";

pub struct YubicoClient {
    client_id: usize,
    api_key: String,
    client: Client,
}

#[derive(Builder, Debug)]
#[builder(setter(into))]
pub struct VerificationResponse {
    pub otp: String,
    pub nonce: String,
    pub h: String,
    pub t: String,
    pub status: State,
    #[builder(default)]
    pub timestamp: Option<String>,
    #[builder(default)]
    pub sessioncounter: Option<String>,
    #[builder(default)]
    pub sessionuse: Option<String>,
    #[builder(default)]
    pub sl: usize,
}

#[derive(Serialize)]
pub struct VerificationRequest {
    otp: String,
    id: String,
    timestamp: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sl: Option<String>,
}

impl YubicoClient {
    pub fn new(client_id: usize, api_key: String) -> YubicoClient {
        YubicoClient {
            client_id,
            api_key,
            client: Client::new(),
        }
    }

    pub async fn verify(&self, otp: &str) -> Result<VerificationResponse, String> {
        let request = VerificationRequest {
            otp: otp.to_string(),
            id: (self.client_id).to_string(),
            timestamp: "1".to_string(),
            nonce: Alphanumeric.sample_string(&mut rand::thread_rng(), 16),
            sl: None,
        };

        let body = self
            .send_request(&request)
            .await
            .map_err(|e| format!("HTTP request error: {:?}", e))?;

        let response = parse_response_body(&body)?;

        Ok(response)
    }

    async fn send_request(&self, request: &VerificationRequest) -> Result<String, reqwest::Error> {
        let text = &self
            .client
            .get(YUBICO_API_URL)
            .query(&request)
            .send()
            .await?
            .text()
            .await?;

        Ok(text.to_owned())
    }
}

fn parse_response_body(body: &str) -> Result<VerificationResponse, String> {
    let mut verification_response = VerificationResponseBuilder::default();
    let split = body.split("\r\n");
    for line in split {
        if let Some(x) = line.split_once('=') {
            let key = x.0;
            let value = x.1.trim();
            match key {
                "otp" => {
                    verification_response.otp(value);
                }
                "nonce" => {
                    verification_response.nonce(value);
                }
                "h" => {
                    verification_response.h(value);
                }
                "t" => {
                    verification_response.t(value);
                }
                "status" => {
                    if let Ok(state) = State::from_str(value) {
                        verification_response.status(state);
                    } else {
                        return Err("Unable to parse response".to_string());
                    }
                }
                "timestamp" => {
                    verification_response.timestamp(Some(value.to_string()));
                }
                "sessioncounter" => {
                    verification_response.sessioncounter(Some(value.to_string()));
                }
                "sessionuse" => {
                    verification_response.sessionuse(Some(value.to_string()));
                }
                "sl" => {
                    if let Ok(value) = usize::from_str(value) {
                        verification_response.sl(value);
                    } else {
                        return Err("Unable to parse response".to_string());
                    }
                }
                _ => {
                    println!(
                        "Unable to match key {} with value {} to any variable",
                        key, value
                    )
                }
            }
        }
    }

    let response = verification_response
        .build()
        .map_err(|e| format!("Unable to build response: {:?}", e))?;

    Ok(response)
}
