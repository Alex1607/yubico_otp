use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose};
use derive_builder::Builder;
use hmac::{Hmac, Mac};
use rand::distributions::{Alphanumeric, DistString};
use reqwest::Client;
use sha1::Sha1;

use crate::response_state::State;

const YUBICO_API_URL: &str = "https://api.yubico.com/wsapi/2.0/verify";

pub struct YubicoClient {
    client_id: usize,
    api_key: Option<Vec<u8>>,
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

pub struct VerificationRequest {
    otp: String,
    id: String,
    timestamp: String,
    nonce: String,
    h: Option<String>,
    sl: Option<String>,
}

impl YubicoClient {
    pub fn new(client_id: usize, api_key: Option<String>) -> YubicoClient {
        YubicoClient {
            client_id,
            api_key: if let Some(..) = api_key {
                Some(general_purpose::STANDARD.decode(api_key.unwrap()).unwrap())
            } else {
                None
            },
            client: Client::new(),
        }
    }

    pub async fn verify(&self, otp: &str) -> Result<VerificationResponse, String> {
        let mut request = VerificationRequest {
            id: (self.client_id).to_string(),
            nonce: Alphanumeric.sample_string(&mut rand::thread_rng(), 16),
            otp: otp.to_string(),
            timestamp: "1".to_string(),
            sl: None,
            h: None,
        };

        if self.api_key.is_some() {
            let string = encode_request_query(&request);

            let signed_request = sign_request(self.api_key.as_ref().unwrap(), string.as_str());

            request.h = Some(signed_request);
        }

        let body = self
            .send_request(&encode_request_query(&request))
            .await
            .map_err(|e| format!("HTTP request error: {:?}", e))?;

        let response = parse_response_body(&body)?;

        Ok(response)
    }

    async fn send_request(&self, request: &str) -> Result<String, reqwest::Error> {
        let text = &self
            .client
            .get(format!("{}?{}", YUBICO_API_URL, request))
            .send()
            .await?
            .text()
            .await?;

        Ok(text.to_owned())
    }
}

fn sign_request(key: &[u8], query: &str) -> String {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(query.as_ref());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    general_purpose::STANDARD.encode(code_bytes)
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
                        return Err("Unable to parse status response".to_string());
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
                        return Err("Unable to parse sl response".to_string());
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

/// This methode generates the query string for the request send to the yubico api.
/// Sadly I had to write this on my own and couldn't use `serde_qs` since it didn't
/// preserve the order of attributes in the struct, which is important for the signing
/// of the request.
///
/// # Arguments
///
/// * `request`:
///
/// returns: String
///
/// # Examples
///
/// ```
///
/// ```
fn encode_request_query(request: &VerificationRequest) -> String {
    let mut response_parts = Vec::new();

    response_parts.push(format!("id={}", request.id));
    response_parts.push(format!("nonce={}", request.nonce));
    response_parts.push(format!("otp={}", request.otp));
    response_parts.push(format!("timestamp={}", request.timestamp));
    if request.sl.is_some() {
        response_parts.push(format!("sl={}", request.sl.as_ref().unwrap()));
    }
    if request.h.is_some() {
        response_parts.push(format!("h={}", request.h.as_ref().unwrap()));
    }

    response_parts.join("&")
}
