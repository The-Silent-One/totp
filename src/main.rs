use base32::{self, Alphabet};
use chrono::{TimeZone, Utc};
use hmac::{Hmac, Mac};
use indicatif::ProgressBar;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const MSG: &str = "HMAC can take key of any size";

fn hmac_sha(crypto: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha1::new_from_slice(key).expect(MSG);
        mac.update(data);
        let result = mac.finalize();
        return result.into_bytes().to_vec();
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect(MSG);
        mac.update(data);
        let result = mac.finalize();
        return result.into_bytes().to_vec();
    }

    fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha512::new_from_slice(key).expect(MSG);
        mac.update(data);
        let result = mac.finalize();
        return result.into_bytes().to_vec();
    }

    let res: Vec<u8>;
    match crypto {
        "sha1" => res = hmac_sha1(key, data),
        "sha256" => res = hmac_sha256(key, data),
        "sha512" => res = hmac_sha512(key, data),
        _ => unimplemented!("Algorithm funciton not supported: {}", crypto),
    };
    return res;
}

fn get_unixtime() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

fn generate_totp(key: &str, time: u64, digits: u8, crypto: &str, protocol: &str) -> String {
    let msg: &[u8] = &time.to_be_bytes();
    let k: Vec<u8>;

    match protocol {
        "raw" => k = key.as_bytes().to_vec(),
        "base32" => {
            k = base32::encode(Alphabet::Rfc4648 { padding: false }, key.as_bytes())
                .as_bytes()
                .to_vec();
        }
        _ => unimplemented!("Protocol not supported: {}", protocol),
    };

    let hash: Vec<u8> = hmac_sha(crypto, &k, msg);
    let offset: usize = (hash.last().unwrap() & 15) as usize;
    let result: u32 =
        u32::from_be_bytes(hash[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;

    return format!(
        "{1:00$}",
        digits as usize,
        result % 10_u32.pow(digits as u32)
    );
}

#[allow(dead_code)]
fn hexstring(n: &str) -> String {
    let tmp: u64 = n.parse::<u64>().unwrap();
    return format!("{:0>16}", format!("{:X}", tmp));
}

#[allow(dead_code)]
fn test_vectors() {
    let seed: String = "3132333435363738393031323334353637383930".to_string();
    let seed32: String =
        "3132333435363738393031323334353637383930313233343536373839303132".to_string();
    let seed64: String = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334".to_string();
    let t0: u64 = 0;
    let x: u64 = 30;

    let times: Vec<u64> = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ]
    .to_vec();

    println!("| Time (sec)         | Time (UTC)            | T (HEX)        | TOTP   | Mode |");
    for time in times {
        let steps: u64 = (time - t0) / x;
        let hex_steps = hexstring(&steps.to_string());
        let t = Utc.timestamp_opt(time as i64, 0).unwrap();

        println!(
            "|{:0>20}|{}|{}|{}|sha1  |",
            time,
            t,
            hex_steps,
            generate_totp(&seed, steps.clone(), 8, "sha1", "raw"),
        );
        println!(
            "|{:0>20}|{}|{}|{}|sha256|",
            time,
            t,
            hex_steps,
            generate_totp(&seed32, steps.clone(), 8, "sha256", "raw"),
        );
        println!(
            "|{:0>20}|{}|{}|{}|sha512|",
            time,
            t,
            hex_steps,
            generate_totp(&seed64, steps.clone(), 8, "sha512", "raw"),
        );
        println!("+--------------------+-----------------------+----------------+--------+------+")
    }
}

fn main() {
    let key: &str = "very_secret_key";
    let t0: u64 = 0;
    let x: u64 = 5;
    let digits: u8 = 8;

    let bar = ProgressBar::new(x);
    loop {
        let time: u64 = (get_unixtime() - t0) / x;
        let token: String = generate_totp(key, time, digits, "sha512", "raw");
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("{}", token);
        for _ in 0..x {
            bar.inc(1);
            sleep(Duration::from_secs(1));
        }
        bar.reset();
    }
}
