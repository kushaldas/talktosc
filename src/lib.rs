//! This crate defines APDUs and related functions to talk to the OpenPGP applet on a smartcard.
//!
//! Right now it is in the inital stage of the development.
use apdus::APDU;
use pcsc::*;
use std::str;

pub mod apdus;
pub mod errors;
pub mod tlvs;
pub mod response;

/// Creates a new connection to the card attached to the first reader and returns the connection,
/// or the related error.
///
/// # Example
///
/// ```
/// use talktosc::*;
///
/// let card = create_connection().unwrap();
/// ```
pub fn create_connection() -> Result<Card, errors::TalktoSCError> {
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => return Err(errors::TalktoSCError::ContextError(err.to_string())),
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            return Err(errors::TalktoSCError::ReaderError(err.to_string()));
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            return Err(errors::TalktoSCError::MissingReaderError);
        }
    };
    //println!("Using reader: {:?}", reader);

    // Connect to the card.
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(card) => card,
        Err(Error::NoSmartcard) => {
            return Err(errors::TalktoSCError::MissingSmartCardError);
        }
        Err(err) => {
            return Err(errors::TalktoSCError::SmartCardConnectionError(
                err.to_string(),
            ));
        }
    };
    Ok(card)
}

/// Disconnects the card via Disposition::LeaveCard
pub fn disconnect(card: Card) {
    let _ = card.disconnect(Disposition::LeaveCard);
}

//pub fn sendapdu(card: &Card, apdu: &[u8]) -> Vec<u8> {
//let mut resp_buffer = [0; MAX_BUFFER_SIZE];
//let resp = card.transmit(apdu, &mut resp_buffer).unwrap();
//let val = Vec::from(resp);
//return val;
//}

/// Sends the given APDU (if required in chained way) to the card and returns the response as a
/// vector of `u8`.
pub fn sendapdu(card: &Card, apdu: apdus::APDU) -> Vec<u8> {
    let l = apdu.iapdus.len();
    let mut i = 0;
    let mut res: Vec<u8> = Vec::new();
    for actual_apdu in &apdu {
        let mut resp_buffer = [0; MAX_BUFFER_SIZE];
        let resp = card.transmit(&actual_apdu[..], &mut resp_buffer).unwrap();
        // TODO: Verify the response
        //println!("Received: {:#?}", resp);
        i += 1;
        if i == l {
            // TODO: verify the final response
            res = Vec::from(resp);
        }
    }
    return res;
}

/// Helper function to send the APDU and returns the a Result<Response, errors::TalktoSCError>.
pub fn send_and_parse(card: &Card, apdus: APDU) -> Result<response::Response, errors::TalktoSCError> {
    response::Response::new(sendapdu(&card, apdus))
}

pub fn entry(pin: Vec<u8>) {
    let card = create_connection().unwrap();
    //let select_openpgp: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let select_openpgp = apdus::create_apdu_select_openpgp();
    let resp = send_and_parse(&card, select_openpgp).unwrap();
    println!("Received Final: {:x?}", resp.get_data());

    let resp = send_and_parse(&card, apdus::create_apdu_get_aid()).unwrap();

    println!("Serial number: {}", tlvs::parse_card_serial(resp.get_data()));
    //let get_url_apdu = apdus::create_apdu_get_url();
    //let resp = sendapdu(&card, get_url_apdu);
    //let l = resp.len() - 2;
    //println!(
    //"Received at the end: {}",
    //str::from_utf8(&resp[..l]).unwrap()
    //);
    // Now let us try to verify the pin passed to us.
    //let pin_apdu = apdus::create_apdu_verify_pw1_for_others(pin);
    //let resp = sendapdu(&card, pin_apdu);
    //let l = resp.len() - 2;
    //println!(
    //"Received at the end: {}",
    //str::from_utf8(&resp[..l]).unwrap()
    //);
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
        let comapdu = apdus::APDU::new(0x00, 0x2A, 0x80, 0x86, Some(buffer));
        assert_eq!(comapdu.iapdus.len(), 3);
        assert_eq!(comapdu.iapdus[0][0], 0x10);
        assert_eq!(comapdu.iapdus[1][0], 0x10);
        assert_eq!(comapdu.iapdus[2][0], 0x00);
    }
}
