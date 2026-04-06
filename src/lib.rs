//! This crate defines APDUs and related functions to talk to the OpenPGP applet on a smartcard.
//!
//! Right now it is in the inital stage of the development.
use apdus::APDU;
use pcsc::*;

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

/// Returns a list of all available smart card reader names connected to the system.
///
/// This queries the PC/SC subsystem for all connected readers (e.g. USB card readers,
/// built-in NFC readers). Note that a reader may be present even if no card is inserted.
///
/// # Returns
///
/// A vector of reader name strings. Empty if no readers are connected.
///
/// # Errors
///
/// * [`TalktoSCError::ContextError`] - If the PC/SC context cannot be established
/// * [`TalktoSCError::ReaderError`] - If the reader list cannot be retrieved
///
/// # Example
///
/// ```no_run
/// use talktosc::list_readers;
///
/// let readers = list_readers().unwrap();
/// if readers.is_empty() {
///     println!("No card readers found");
/// } else {
///     for reader in &readers {
///         println!("Reader: {}", reader);
///     }
/// }
/// ```
pub fn list_readers() -> Result<Vec<String>, errors::TalktoSCError> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| errors::TalktoSCError::ContextError(e.to_string()))?;
    let mut readers_buf = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf)
        .map_err(|e| errors::TalktoSCError::ReaderError(e.to_string()))?;
    Ok(readers.map(|r| r.to_str().unwrap_or("").to_string()).collect())
}

/// Returns the unique ident for a connected card.
///
/// The ident is formatted as `"MANUFACTURER:SERIAL"` (e.g. `"0006:00000001"`
/// for a Yubico card with serial 1). This is the same format used by the
/// `openpgp-card` crate's `ApplicationIdentifier::ident()`.
///
/// This function SELECTs the OpenPGP applet and reads the Application
/// Identifier (AID) to extract the manufacturer code (bytes 8-9) and
/// serial number (bytes 10-13).
///
/// # Arguments
///
/// * `card` - A reference to an already-connected card (from `create_connection()`
///   or `create_connection_by_ident()`)
///
/// # Returns
///
/// The card ident string in uppercase hex, e.g. `"0006:00000001"`.
///
/// # Errors
///
/// * [`TalktoSCError::PinError`] - If the OpenPGP applet cannot be selected
/// * [`TalktoSCError::SmartCardConnectionError`] - If the AID response is too short
///
/// # Example
///
/// ```no_run
/// use talktosc::{create_connection, get_card_ident_from_card, disconnect};
///
/// let card = create_connection().unwrap();
/// let ident = get_card_ident_from_card(&card).unwrap();
/// println!("Card ident: {}", ident); // e.g. "0006:00000001"
/// disconnect(card);
/// ```
pub fn get_card_ident_from_card(card: &Card) -> Result<String, errors::TalktoSCError> {
    // Select OpenPGP applet
    let select_apdu = apdus::create_apdu_select_openpgp();
    send_and_parse(card, select_apdu)?;

    // Get AID
    let resp = send_and_parse(card, apdus::create_apdu_get_aid())?;
    let data = resp.get_data();

    // AID format: bytes 8-9 = manufacturer, bytes 10-13 = serial
    if data.len() < 14 {
        return Err(errors::TalktoSCError::SmartCardConnectionError(
            "AID response too short".to_string(),
        ));
    }

    let manufacturer = ((data[8] as u16) << 8) | (data[9] as u16);
    let serial = ((data[10] as u32) << 24)
        | ((data[11] as u32) << 16)
        | ((data[12] as u32) << 8)
        | (data[13] as u32);

    Ok(format!("{:04X}:{:08X}", manufacturer, serial))
}

/// Lists all connected OpenPGP smart cards with their idents.
///
/// Iterates all connected readers, attempts to connect to each one,
/// SELECTs the OpenPGP applet, and reads the AID to determine the
/// card's ident. Readers without a card or without an OpenPGP applet
/// are silently skipped.
///
/// # Returns
///
/// A vector of `(reader_name, ident)` tuples. The `reader_name` is the
/// PC/SC reader string (e.g. `"Yubico Yubikey OTP FIDO CCID 00 00"`)
/// and `ident` is the card identifier (e.g. `"0006:00000001"`).
///
/// # Errors
///
/// * [`TalktoSCError::ContextError`] - If the PC/SC context cannot be established
/// * [`TalktoSCError::ReaderError`] - If the reader list cannot be retrieved
///
/// # Example
///
/// ```no_run
/// use talktosc::list_cards;
///
/// let cards = list_cards().unwrap();
/// if cards.is_empty() {
///     println!("No OpenPGP cards found");
/// } else {
///     for (reader, ident) in &cards {
///         println!("Reader: {}", reader);
///         println!("  Card ident: {}", ident);
///     }
/// }
/// ```
pub fn list_cards() -> Result<Vec<(String, String)>, errors::TalktoSCError> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| errors::TalktoSCError::ContextError(e.to_string()))?;
    let mut readers_buf = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf)
        .map_err(|e| errors::TalktoSCError::ReaderError(e.to_string()))?;

    let mut result = Vec::new();
    for reader in readers {
        let reader_name = reader.to_str().unwrap_or("").to_string();
        // Try to connect to this reader
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Try to get the ident
        if let Ok(ident) = get_card_ident_from_card(&card) {
            result.push((reader_name, ident));
        }
        let _ = card.disconnect(Disposition::LeaveCard);
    }
    Ok(result)
}

/// Creates a connection to the card matching the given ident.
///
/// The ident format is `"MANUFACTURER:SERIAL"` (e.g. `"0006:00000001"`).
/// This iterates all connected readers, SELECTs the OpenPGP applet on each,
/// reads the AID to determine the ident, and returns a connection to the
/// card with the matching ident.
///
/// Use this when multiple smart cards are connected and you need to target
/// a specific one. The ident can be obtained from [`list_cards()`] or
/// [`get_card_ident_from_card()`].
///
/// # Arguments
///
/// * `ident` - The card identifier to search for (case-insensitive)
///
/// # Returns
///
/// A `Card` connection to the matching smart card.
///
/// # Errors
///
/// * [`TalktoSCError::SmartCardConnectionError`] - If no card with the given ident is found
/// * [`TalktoSCError::ContextError`] - If the PC/SC context cannot be established
/// * [`TalktoSCError::MissingSmartCardError`] - If the card was found but reconnection failed
///
/// # Example
///
/// ```no_run
/// use talktosc::{list_cards, create_connection_by_ident, send_and_parse, apdus, disconnect};
///
/// // First, discover available cards
/// let cards = list_cards().unwrap();
/// let (reader, ident) = &cards[0];
/// println!("Connecting to {} on {}", ident, reader);
///
/// // Connect to a specific card by ident
/// let card = create_connection_by_ident(ident).unwrap();
///
/// // Use the card
/// let select = apdus::create_apdu_select_openpgp();
/// let resp = send_and_parse(&card, select).unwrap();
/// println!("Selected OpenPGP applet: {:?}", resp.get_data());
///
/// disconnect(card);
/// ```
pub fn create_connection_by_ident(ident: &str) -> Result<Card, errors::TalktoSCError> {
    let target = ident.to_ascii_uppercase();

    let ctx = Context::establish(Scope::User)
        .map_err(|e| errors::TalktoSCError::ContextError(e.to_string()))?;
    let mut readers_buf = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf)
        .map_err(|e| errors::TalktoSCError::ReaderError(e.to_string()))?;

    // Collect reader names that match
    let mut matching_reader: Option<String> = None;

    for reader in readers {
        let reader_name = reader.to_str().unwrap_or("").to_string();
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let card_ident = get_card_ident_from_card(&card).ok();
        let _ = card.disconnect(Disposition::LeaveCard);

        if card_ident.as_deref() == Some(&target) {
            matching_reader = Some(reader_name);
            break;
        }
    }

    let reader_name = matching_reader.as_ref().ok_or_else(|| {
        errors::TalktoSCError::SmartCardConnectionError(
            format!("Card with ident '{}' not found", ident),
        )
    })?.clone();

    // Re-establish context and connect to the matching reader
    let ctx = Context::establish(Scope::User)
        .map_err(|e| errors::TalktoSCError::ContextError(e.to_string()))?;
    let mut readers_buf2 = [0; 2048];
    let readers = ctx.list_readers(&mut readers_buf2)
        .map_err(|e| errors::TalktoSCError::ReaderError(e.to_string()))?;

    for reader in readers {
        if reader.to_str().unwrap_or("") == reader_name {
            let card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY)
                .map_err(|e| match e {
                    Error::NoSmartcard => errors::TalktoSCError::MissingSmartCardError,
                    err => errors::TalktoSCError::SmartCardConnectionError(err.to_string()),
                })?;
            return Ok(card);
        }
    }

    Err(errors::TalktoSCError::MissingSmartCardError)
}

/// Disconnects the card cleanly via `Disposition::LeaveCard`.
///
/// This should be called when you are done communicating with the card.
/// The card remains powered and available for other applications.
///
/// # Arguments
///
/// * `card` - The card connection to disconnect (consumed by this call)
///
/// # Example
///
/// ```no_run
/// use talktosc::{create_connection, disconnect};
///
/// let card = create_connection().unwrap();
/// // ... use the card ...
/// disconnect(card);
/// ```
pub fn disconnect(card: Card) {
    let _ = card.disconnect(Disposition::LeaveCard);
}

//pub fn sendapdu(card: &Card, apdu: &[u8]) -> Vec<u8> {
//let mut resp_buffer = [0; MAX_BUFFER_SIZE];
//let resp = card.transmit(apdu, &mut resp_buffer).unwrap();
//let val = Vec::from(resp);
//return val;
//}

/// Sends the given APDU to the card and returns the raw response bytes.
///
/// If the APDU is too large for a single transmission, it is automatically
/// sent in chained mode (multiple APDUs with the CLA chaining bit set).
/// Only the response from the final APDU in the chain is returned.
///
/// # Arguments
///
/// * `card` - A reference to the connected card
/// * `apdu` - The APDU to send (may contain multiple chained internal APDUs)
///
/// # Returns
///
/// The raw response bytes from the card, including the status word (SW1/SW2)
/// as the last two bytes.
///
/// # Example
///
/// ```no_run
/// use talktosc::{create_connection, sendapdu, apdus, disconnect};
///
/// let card = create_connection().unwrap();
/// let select = apdus::create_apdu_select_openpgp();
/// let response = sendapdu(&card, select);
/// println!("Response: {:02X?}", response);
/// disconnect(card);
/// ```
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

/// Sends an APDU to the card and parses the response.
///
/// This is a convenience wrapper around [`sendapdu`] that parses the raw
/// response bytes into a [`Response`](response::Response) struct, which
/// separates the data from the status word.
///
/// # Arguments
///
/// * `card` - A reference to the connected card
/// * `apdus` - The APDU to send
///
/// # Returns
///
/// A parsed [`Response`](response::Response) containing the data and status.
///
/// # Errors
///
/// * [`TalktoSCError::ResponseError`] - If the response is malformed
///
/// # Example
///
/// ```no_run
/// use talktosc::{create_connection, send_and_parse, apdus, disconnect};
///
/// let card = create_connection().unwrap();
///
/// // Select the OpenPGP applet
/// let select = apdus::create_apdu_select_openpgp();
/// let resp = send_and_parse(&card, select).unwrap();
/// println!("Status: {:02X}{:02X}", resp.sw1, resp.sw2);
/// println!("Data: {:02X?}", resp.get_data());
///
/// disconnect(card);
/// ```
pub fn send_and_parse(card: &Card, apdus: APDU) -> Result<response::Response, errors::TalktoSCError> {
    response::Response::new(sendapdu(&card, apdus))
}

pub fn entry(_pin: Vec<u8>) {
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
    //let pin_apdu = apdus::create_apdu_verify_pw1_for_others(_pin);
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
