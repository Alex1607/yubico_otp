# Rust YubicoOTP

This crate allows you to verify Yubico OTPs. To get details about what a Yubico OTP is you can read about it here: https://developers.yubico.com/OTP/

In order to use this crate you should first check the OTP of the user with the is_valid_otp function. If the OTP has the correct format you can send the OTP to
Yubico for verification. To do that you will have to create a YubicoClient with your credentials. You can then call the verify function on it to send the
request. Check if the result has the state Ok, if its any other state the OTP is invalid!

In case the state was Ok you will probably also want to check the public id of the key to compare it against the one you have on record. To get the public id of
any OTP you can call the get_public_id function.