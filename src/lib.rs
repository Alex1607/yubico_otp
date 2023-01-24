mod response_state;
mod yubico_client;

const OTP_MIN_LENGTH: usize = 32;
const OTP_MAX_LENGTH: usize = 48;

pub fn is_valid_otp(otp: &str) -> bool {
    if (otp.len() < OTP_MIN_LENGTH) || (otp.len() > OTP_MAX_LENGTH) {
        return false;
    }

    return otp
        .chars()
        .map(|c| c as u32)
        .all(|c| (0x20..=0x7E).contains(&c));
}

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
    use super::*;
    use crate::yubico_client::YubicoClient;

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

        assert!(valid_otp.ok().is_some());
        assert!(another_valid_otp.ok().is_some());
        assert!(invalid_otp.err().is_some());
    }

    //TODO: Make a more decent test for this, currently its using the client_id and api_key from the
    //      Test Vectors site: https://developers.yubico.com/OTP/Specifications/Test_vectors.html
    //      However the OTP will always return `ReplayedOtp` and not `Ok` which is unfortunate.
    //      Should be enough for the start tho to see if the http requests are successful.
    #[tokio::test]
    async fn test_yubico_client() {
        //Hit: Do NOT use the credentials here, these are example credentials from the documentation!
        //Instead get your own api_key and client_id from here: https://upgrade.yubico.com/getapikey/
        let client = YubicoClient::new(1, "mG5be6ZJU1qBGz24yPh/ESM3UdU=".to_string());

        let x = client
            .verify("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
            .await
            .unwrap();

        assert_eq!(x.status, State::ReplayedOtp)
    }
}
