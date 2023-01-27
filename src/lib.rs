//! # YubiOTP
//!
//! This crate allows you to verify Yubico OTPs.
//! To get details about what a Yubico OTP is, you can read about it here: <https://developers.yubico.com/OTP/>
//!
//! In order to use this crate you should first check the OTP of the user with the `is_valid_otp` function.
//! If the OTP has the correct format, you can send the OTP to Yubico for verification. To do that, you
//! will have to create a `YubicoClient` with your credentials.
//! You can then call the `verify` function on it to send the request.
//! Check if the result has the state `Ok`, if it's any other state the OTP is invalid!
//!
//! In case the state was `Ok` you will probably also want to check the public id of the key to compare it against the one you have on record.
//! To get the public id of any OTP you can call the `get_public_id` function.

mod response_state;
pub mod yubico_client;

const OTP_MIN_LENGTH: usize = 32;
const OTP_MAX_LENGTH: usize = 48;

/// Validates if a give OTP if in a valid format.
///
/// # Arguments
///
/// * `otp`: The OTP which format should be checked
///
/// returns: bool
///
/// # Examples
///
/// ```
/// assert!(yubi_opt::is_valid_otp("cccjgjgkhcbbcvchfkfhiiuunbtnvgihdfiktncvlhck"));
/// ```
pub fn is_valid_otp(otp: &str) -> bool {
    if (otp.len() < OTP_MIN_LENGTH) || (otp.len() > OTP_MAX_LENGTH) {
        return false;
    }

    return otp
        .chars()
        .map(|c| c as u32)
        .all(|c| (0x20..=0x7E).contains(&c));
}

/// Will return the public id of an OTP.
///
/// # Arguments
///
/// * `otp`: OTP from which the public id should be extracted
///
/// returns: Result<&str, &str>
///
/// # Examples
///
/// ```
/// let public_id = yubi_opt::get_public_id("cccjgjgkhcbbcvchfkfhiiuunbtnvgihdfiktncvlhck").unwrap();
/// assert_eq!(public_id, "cccjgjgkhcbb")
/// ```
pub fn get_public_id(otp: &str) -> Result<&str, &str> {
    if !is_valid_otp(otp) {
        return Err("OTP is invalid");
    }

    //Last 32 chars will always be the unique passcode
    Ok(otp.split_at(otp.len() - 32).0)
}

#[cfg(test)]
mod tests {
    use crate::response_state::State;
    use crate::yubico_client::YubicoClient;

    use super::*;

    #[test]
    fn test_opt_validator() {
        let valid_otp = is_valid_otp("cccjgjgkhcbbcvchfkfhiiuunbtnvgihdfiktncvlhck");
        let another_valid_otp = is_valid_otp("cccjgjgkhcbbgefdkbbditfjrlniggevfhenublfnrev");
        let invalid_otp_char = is_valid_otp("cccjgjgkhcbbcvchfkツhiiuunbtnvgihdfiktncvlhck");
        let invalid_otp_length = is_valid_otp("gefdkbbditfjrlniggevfh");

        assert!(valid_otp);
        assert!(another_valid_otp);
        assert_eq!(invalid_otp_char, false);
        assert_eq!(invalid_otp_length, false);
    }

    #[test]
    fn test_get_public_id() {
        let valid_otp = get_public_id("cccjgjgkhcbbcvchfkfhiiuunbtnvgihdfiktncvlhck");
        let another_valid_otp = get_public_id("cccjgjgkhcbbgefdkbbditfjrlniggevfhenublfnrev");
        let invalid_otp = get_public_id("gefdkbbditfjrlniggevfh");

        assert_eq!(valid_otp.ok().unwrap(), "cccjgjgkhcbb");
        assert_eq!(another_valid_otp.ok().unwrap(), "cccjgjgkhcbb");
        assert!(invalid_otp.err().is_some());
    }

    //TODO: Make a more decent test for this, currently its using the client_id and api_key from the
    //      Test Vectors site: https://developers.yubico.com/OTP/Specifications/Test_vectors.html
    //      However the OTP will always return `ReplayedOtp` and not `Ok` which is unfortunate.
    //      Should be enough for the start tho to see if the http requests are successful.
    #[test]
    fn test_yubico_client() {
        //Hit: Do NOT use the credentials here, these are example credentials from the documentation!
        //Instead get your own api_key and client_id from here: https://upgrade.yubico.com/getapikey/
        let client = YubicoClient::new(1, None);

        let x = client
            .verify("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
            .unwrap();

        assert_eq!(x.state, State::ReplayedOtp)
    }
}
