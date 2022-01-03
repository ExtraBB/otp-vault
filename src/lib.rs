use ring::{hmac};
use std::time::{SystemTime, UNIX_EPOCH};
use bitreader::BitReader;

pub struct TokenSource {
    pub key: String,
    pub interval_seconds: u64,
    pub algorithm: hmac::Algorithm,
    pub digits: u32
}

impl TokenSource {
    pub fn generate_totp_token(self: &TokenSource) -> u32 {
        let counter = calculate_totp_counter(self.interval_seconds);
        let bytes = &u64::to_be_bytes(counter);
        return generate_hotp_token(self, bytes)
    }
}

fn calculate_totp_counter(interval: u64) -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    return since_the_epoch.as_secs() / interval;
}

fn generate_hotp_token(source: &TokenSource, bytes: &[u8]) -> u32 {
    let tag = generate_hmac(source.algorithm, &source.key, bytes);
    let truncated = truncate(tag.as_ref());
    return truncated % u32::pow(10, source.digits);
}

fn generate_hmac(algorithm: hmac::Algorithm, key: &str, bytes: &[u8]) -> ring::hmac::Tag {
    let key = hmac::Key::new(algorithm, &key.as_bytes());
    return hmac::sign(&key, bytes);
}

fn truncate(mac: &[u8]) -> u32 {
    let last_byte = &mac[mac.len() - 1..];
    let mut bit_reader = BitReader::new(last_byte);
    let _unused_bits = bit_reader.read_u8(4).unwrap();
    let least_significant_bits = bit_reader.read_u8(4).unwrap();
    return extract31(mac, least_significant_bits as usize);
}

fn extract31(mac: &[u8], i: usize) -> u32{
    let mac_slice = &mac[i..i+4];
    let mut bit_reader = BitReader::new(mac_slice);
    let _unused_bits = bit_reader.read_u8(1).unwrap();
    return bit_reader.read_u32(31).unwrap();
}