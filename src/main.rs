use ring::{hmac};
use otp_vault;

fn main() {
    let token_source = otp_vault::TokenSource {
        key: String::from("test"),
        interval_seconds: 30,
        algorithm: hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        digits: 6
    };

    let token = token_source.generate_totp_token();
    println!("{}", token);
}