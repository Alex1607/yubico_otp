use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose};
use derive_builder::Builder;
use hmac::{Hmac, Mac};
use rand::distributions::{Alphanumeric, DistString};
use sha1::Sha1;

use crate::response_state::State;

//Yubico decommissioned the old api1, api2 etc servers: https://status.yubico.com/2020/02/25/decommissioning-old-yubiotp-api-validation-servers/
const YUBICO_API_URL: &str = "https://api.yubico.com/wsapi/2.0/verify";

pub struct YubicoClient {
    client_id: usize,
    key: Option<Vec<u8>>,
}

#[derive(Builder, Debug)]
#[builder(setter(into))]
pub struct VerificationResponse {
    pub otp: String,
    pub nonce: String,
    pub h: String,
    pub t: String,
    pub state: State,
    #[builder(default)]
    pub timestamp: Option<String>,
    #[builder(default)]
    pub sessioncounter: Option<String>,
    #[builder(default)]
    pub sessionuse: Option<String>,
    #[builder(default)]
    //TODO: Update SL default value to be missing instead of being 0
    pub sl: usize,
    response_map: BTreeMap<String, String>,
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
    /// Creates a new YubicoClient for verifying OTPs.
    ///
    /// # Arguments
    ///
    /// * `client_id`: Your Client Id given by you by Yubico
    /// * `key`: Optional, if present it will be using to sign the requests
    ///
    /// returns: YubicoClient
    ///
    pub fn new(client_id: usize, api_key: Option<String>) -> YubicoClient {
        YubicoClient {
            client_id,
            key: if let Some(..) = api_key {
                Some(general_purpose::STANDARD.decode(api_key.unwrap()).unwrap())
            } else {
                None
            },
        }
    }

    /// Verify an OTP against the Yubico API.
    /// Make sure to test the state from the returned ``VerificationResponse``. You should only proceed if the state is `Ok`!
    ///
    /// # Arguments
    ///
    /// * `otp`: OTP to be verified
    ///
    /// returns: Result<VerificationResponse, String>
    ///
    /// # Examples
    ///
    /// ```
    ///  use yubi_opt::yubico_client::YubicoClient;
    ///  let client = YubicoClient::new(1, None);
    ///  match client.verify("Some OTP") {
    ///      Ok(_) => {
    ///         println!("Request was successful. Do not forget to test for the Ok state!");
    ///      }
    ///      Err(_) => {
    ///          println!("Oh no, an error occurred");
    ///      }
    ///  }
    /// ```
    pub fn verify(&self, otp: &str) -> Result<VerificationResponse, String> {
        let mut request = VerificationRequest {
            id: (self.client_id).to_string(),
            nonce: Alphanumeric.sample_string(&mut rand::thread_rng(), 16),
            otp: otp.to_string(),
            timestamp: "1".to_string(),
            sl: None,
            h: None,
        };

        if self.key.is_some() {
            let string = encode_request_query(&request);

            let signed_request = calculate_signature(self.key.as_ref().unwrap(), string.as_str());

            request.h = Some(signed_request);
        }

        let body = self
            .send_request(&encode_request_query(&request))
            .map_err(|e| format!("HTTP request error: {e:?}"))?;

        let response = parse_response_body(&body)?;

        //Only verify signature if there should be one. Additional skip this if the yubico api already noticed a bad signature
        if self.key.is_some()
            && response.state != State::BadSignature
            && !verify_signature(self.key.as_ref().unwrap(), &response)
        {
            return Err("Signature mismatch! Maybe your key / id is wrong.".to_string());
        }

        Ok(response)
    }

    fn send_request(&self, request: &str) -> Result<String, ureq::Error> {
        let text = ureq::get(format!("{YUBICO_API_URL}?{request}").as_ref())
            .call()?
            .into_string()?;

        Ok(text)
    }
}

fn calculate_signature(key: &[u8], text: &str) -> String {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).unwrap();
    mac.update(text.as_ref());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    general_purpose::STANDARD.encode(code_bytes)
}

fn verify_signature(key: &[u8], response: &VerificationResponse) -> bool {
    let mut response_string = response
        .response_map
        .iter()
        .filter(|entry| entry.0.ne("h"))
        .map(|x| format!("{}={}&", x.0, x.1))
        .collect::<String>();

    response_string.pop();

    calculate_signature(key, response_string.as_str()).eq(&response.h)
}

fn parse_response_body(body: &str) -> Result<VerificationResponse, String> {
    let mut verification_response = VerificationResponseBuilder::default();
    let mut temp_response_map: BTreeMap<String, String> = BTreeMap::new();
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
                        verification_response.state(state);
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
                    println!("Unable to match key {key} with value {value} to any variable", )
                }
            }
            temp_response_map.insert(key.to_string(), value.to_string());
        }
    }

    verification_response.response_map(temp_response_map);

    let response = verification_response
        .build()
        .map_err(|e| format!("Unable to build response: {e:?}"))?;

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
