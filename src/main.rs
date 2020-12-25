use rpassword;
use talktosc::*;

use std::io::Read;
use std::{fs::File, print};

fn get_my_tlv(filename: &str) -> tlvs::TLV {
    let mut f = File::open(filename).expect("no file found");
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    let big_box = &tlvs::read_list(buffer, true)[0];
    big_box.clone()
}

fn main() {
    //let pass = rpassword::read_password_from_tty(Some("Password: ")).unwrap();
    //entry(pass.into_bytes());
    //let big_box = get_my_tlv("./data/6e_information_for_25519.binary");
    //let t = big_box.get_encryption_algo_attributes().unwrap();
    //println!("This card's algos {}", tlvs::hexify(t));
    //let t = big_box.get_name().unwrap();
    //println!("The name is {}", String::from_utf8(t).unwrap());
    //let t = big_box.get_historical_bytes().unwrap();
    //println!("This card's SIGN algo {}", tlvs::hexify(t));
    //let t = big_box.get_fingerprints().unwrap();
    //let sig_f = &t[0..20];
    //println!("This card's SIGN fingerprint {}", tlvs::hexify(sig_f.iter().cloned().collect()));
    let mut f = File::open("data/capabilities_tlv.binary").expect("no file found");
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    let big_box = &tlvs::read_list(buffer, true);
    let first = big_box[0].clone();
    let data = first.find_tag(0xC2).unwrap();
    dbg!(data);
    //for bigb in big_box {
    //let ts = bigb.subs.clone();
    //for tlv in ts {
    //dbg!(tlvs::hex(tlv.t));
    //dbg!(tlvs::hex(tlv.l));
    //dbg!(tlv.if_recursive());
    //}
    //}
}
