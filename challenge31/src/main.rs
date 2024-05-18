use std::{
    cmp::max_by,
    thread::sleep,
    time::{Duration, Instant},
};

use rocket::{get, http::Status, local::blocking::Client, routes, Build, Config, Rocket};
use tools::{
    digest::{sha1::Sha1Core, Hmac},
    encode::{
        ascii::from_ascii,
        hex::{from_hex, to_hex},
    },
};

const SECRET_KEY: &[u8; 16] = b"YELLOW SUBMARINE";
const DURATION: u64 = 5;

fn insecure_compare(byte1: &[u8], byte2: &[u8]) -> bool {
    byte1.iter().zip(byte2.iter()).all(|(v1, v2)| {
        sleep(Duration::from_millis(DURATION));
        v1 == v2
    })
}

#[get("/test?<file>&<signature>")]
fn test(file: &str, signature: &str) -> Status {
    if from_hex(signature, true)
        .filter(|v| v.len() == 20)
        .is_some_and(|v| {
            let mut mac = Hmac::<Sha1Core>::new(SECRET_KEY);
            mac.update(&from_ascii(file));
            insecure_compare(&mac.finalize(), &v)
        })
    {
        Status::Ok
    } else {
        Status::InternalServerError
    }
}

fn main() {
    let config = Config::figment().merge(("log_level", "off"));

    let file = "foo";
    let mac = recover_hmac(
        rocket::build().configure(config).mount("/", routes![test]),
        file,
    );
    println!("mac : {}", to_hex(&mac));
    let mut hmac = Hmac::<Sha1Core>::new(SECRET_KEY);
    hmac.update(&from_ascii(file) );

    assert_eq!(mac, hmac.finalize());
}

fn recover_hmac(rocket: Rocket<Build>, file: &str) -> [u8; 20] {
    const SAMPLES : u32 = 5;

    let client = Client::untracked(rocket).unwrap();

    let mut hmac = [0u8; 20];

    for i in 0..hmac.len() {
        let mut max = (0, Duration::ZERO);
        for byte in u8::MIN..=u8::MAX {
            hmac[i] = byte;
            let mut dur = Duration::ZERO;
            for _ in 0..SAMPLES {
                let t1 = Instant::now();
                let resp = client
                    .get(format!("/test?file={file}&signature={}", to_hex(&hmac)))
                    .dispatch();
                if resp.status() == Status::Ok {
                    max = (byte, dur);
                    hmac[i] = max.0; 
                    return hmac;
                }
                dur = dur + Instant::now().duration_since(t1)
            }
            dur = dur / SAMPLES;

            max = max_by(max, (byte, dur), |(_, v1), (_, v2)| v1.cmp(v2));
        }
        hmac[i] = max.0;
        println!("hmac {i} : {}", to_hex(&hmac));
    }
    hmac
}

#[test]
fn test_hmac_over_wire() {
    use rocket::local::blocking::Client;
    use tools::encode::hex::to_hex;

    let client = Client::untracked(rocket::build().mount("/", routes![test])).unwrap();

    // for foo : 274b7c4d98605fcf739a0bf9237551623f415fb8
    let file = "foo";

    let mut hmac = Hmac::<Sha1Core>::new(SECRET_KEY);
    hmac.update(&from_ascii(file));
    let signature = to_hex(&hmac.finalize());

    let mut req = client
        .get(format!("/test?file={file}&signature={signature}"))
        .dispatch();

    assert_eq!(req.status(), Status::Ok);
    req = client
        .get(format!("/test?file={file}&signature=2342992357234"))
        .dispatch();
    assert_eq!(req.status(), Status::InternalServerError);
}
