# Rust YubicoOTP

This crate allows you to verify Yubico OTPs. To get details about what a Yubico OTP is you can read about it
here: https://developers.yubico.com/OTP/

In order to use this crate you should first check the OTP of the user with the `is_valid_otp` function. If the OTP has
the correct format you can send the OTP to
Yubico for verification. To do that you will have to create a YubicoClient with your credentials. You can then call the
verify function on it to send the
request. Check if the result has the state Ok, if its any other state the OTP is invalid!

In case the state was Ok you will probably also want to check the public id of the key to compare it against the one you
have on record. To get the public id of
any OTP you can call the `get_public_id` function.

## Features

This crate supports both synchronous and asynchronous operation:

- **`sync`** (default): Use `YubicoClient` for synchronous verification
- **`async`**: Use `YubicoClientAsync` for async/await verification

You can enable the async feature in your `Cargo.toml`:

```toml
[dependencies]
yubi_opt = { version = "0.2", features = ["async"] }
```

Or enable both features:

```toml
[dependencies]
yubi_opt = { version = "0.2", features = ["sync", "async"] }
```

## Code Examples

### Synchronous Example

*Do NOT use the credentials here, these are example credentials from the documentation!*  
*Instead get your own api_key and client_id from here: https://upgrade.yubico.com/getapikey/*

```rust
use yubi_opt::{is_valid_otp, get_public_id};
use yubi_opt::yubico_client::YubicoClient;
use yubi_opt::response_state::State;

let client = YubicoClient::new(1, None);

let valid = is_valid_otp("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");

let public_id = get_public_id("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");

let x = client
    .verify("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
    .unwrap();

assert_eq!(x.state, State::Ok);
```

### Async Example

```rust
use yubi_opt::{is_valid_otp, get_public_id};
use yubi_opt::yubico_client_async::YubicoClientAsync;
use yubi_opt::response_state::State;

#[tokio::main]
async fn main() {
    let client = YubicoClientAsync::new(1, None);
    
    let valid = is_valid_otp("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");
    
    let public_id = get_public_id("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft");
    
    let x = client
        .verify("vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft")
        .await
        .unwrap();
    
    assert_eq!(x.state, State::Ok);
}
```

After that you can check if a) the public ID is as expected and b) if the state is `Ok`.  
In case the otp is invalid from the `is_valid_otp` check you might return early to not send a request.  