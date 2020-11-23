//! This crate defines APDUs and related functions to talk to the OpenPGP applet on a smartcard.
//!
//! Right now it is in the inital stage of the development.
use pcsc::*;
use std::str;

pub mod apdus;


/// Creates a new connection to the first reader and returns the connection, or `None`.
///
/// # Example
///
/// ```
/// let card = create_connection().unwrap();
/// ```
pub fn create_connection() -> Option<Card>{
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("Failed to establish context: {}", err);
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            eprintln!("Failed to list readers: {}", err);
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            println!("No readers are connected.");
            return None;
        }
    };
    println!("Using reader: {:?}", reader);

    // Connect to the card.
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            println!("A smartcard is not present in the reader.");
            return None;
        }
        Err(err) => {
            eprintln!("Failed to connect to card: {}", err);
            return None;
        }
    };
    Some(card)
}

//pub fn sendapdu(card: &Card, apdu: &[u8]) -> Vec<u8> {
//let mut resp_buffer = [0; MAX_BUFFER_SIZE];
//let resp = card.transmit(apdu, &mut resp_buffer).unwrap();
//let val = Vec::from(resp);
//return val;
//}

pub fn sendapdu(card: &Card, apdu: apdus::APDU) -> Vec<u8> {
    let l = apdu.iapdus.len();
    let mut i = 0;
    let mut res: Vec<u8> = Vec::new();
    for actual_apdu in &apdu {
        let mut resp_buffer = [0; MAX_BUFFER_SIZE];
        let resp = card.transmit(&actual_apdu[..], &mut resp_buffer).unwrap();
        // TODO: Verify the response
        println!("Received: {:#?}", resp);
        i += 1;
        if i == l {
            // TODO: verify the final response
            res = Vec::from(resp);
        }
    }
    return res;
}

pub fn entry() {
    let card = create_connection().unwrap();
    //let select_openpgp: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = sendapdu(&card, select_openpgp);
    println!("Received Final: {:x?}", resp);
    let get_url_apdu = apdus::create_apdu_get_url();
    let resp = sendapdu(&card, get_url_apdu);
    let l = resp.len() - 2;
    println!(
        "Received at the end: {}",
        str::from_utf8(&resp[..l]).unwrap()
    );
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::fs::File;
    use std::io::Read;
    #[test]
    fn test_create_newapdu() {
        let mut f = File::open("./data/foo2.binary").expect("no file found");
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let comapdu = APDU::new(0x00, 0x2A, 0x80, 0x86, Some(buffer));
        assert_eq!(comapdu.iapdus.len(), 3);
        assert_eq!(comapdu.iapdus[0][0], 0x10);
        assert_eq!(comapdu.iapdus[1][0], 0x10);
        assert_eq!(comapdu.iapdus[2][0], 0x00);
    }
}
