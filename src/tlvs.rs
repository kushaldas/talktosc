//! This module implements ISO7816 TLV format.
//!

use std::fmt::{format, UpperHex};

/// A TLV contails the tag, and the length and also the value (data). Our implementation also
/// contains a special `subs` attritbute, which contains a list of composite DOs.
/// Read section  4.4.1 of OpenPGP-smart-card-application-3.4.1.pdf for more details on each tag.
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct TLV {
    /// The tag value as u16. A few of them are composite.
    pub t: u16,
    /// Lenght of the data.
    pub l: u16,
    /// The actual data for the tag.
    pub v: Vec<u8>,
    /// A Vector of TLV structures, only available for composite DO(s).
    pub subs: Vec<TLV>,
}

#[allow(unused)]
impl TLV {
    /// Returns the TAG value as u16.
    pub fn get_t(&self) -> u16 {
        self.t
    }
    /// Returns the length of the contained value as u16.
    pub fn get_l(&self) -> u16 {
        self.l
    }
    /// Returns the value of the tag as a slice of `u8`.
    pub fn get_v(&self) -> &[u8] {
        &self.v[..]
    }
    /// Tells us if there is any recursive TLV(s) present in the `self.sub` vector. `True` only for
    /// the composite DO(s).
    pub fn if_recursive(&self) -> bool {
        if self.subs.len() == 0 {
            false
        } else {
            true
        }
    }

    /// Recursively (depth first) search for any given tag.
    pub fn find_tag(&self, tag: u16) -> Option<TLV> {
        if self.t == tag {
            return Some(self.clone());
        } else if self.if_recursive() {
            for tlv in &self.subs {
                let res = tlv.find_tag(tag);
                match res {
                    Some(res) => return Some(res),
                    _ => (),
                }
            }
        }
        None
    }

    /// Returns the Application identifier (AID), ISO 7816-4 bytes. Between 5-16 bytes in length.
    pub fn get_aid(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0x4F_u16)?;
        Some(tlv.v.clone())
    }

    /// Returns the historical bytes from the smartcard
    /// Most probably historical bytes will have more DOs inside as composite.
    /// We will have to parse those manully into TLV structure.
    pub fn get_historical_bytes(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0x5F52)?;
        Some(tlv.v.clone())
    }

    /// Returns the 60 bytes for the 3 fingerprints.
    /// Signature, decryption, authentication
    ///
    /// # Example
    ///
    /// ```
    /// let sigdata = tlv.get_fingerprints().unwrap();
    /// let sig_f, dec_f, auth_f = parse_fingerprints(sigdata);
    /// println!("This card's Signature fingerprint {}", tlvs::hexify(sig_f.iter().cloned().collect()));
    /// ```
    pub fn get_fingerprints(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0xC5)?;
        Some(tlv.v.clone())
    }

    /// Returns the key information on the card
    ///
    /// This will be only availble under secure messaging, otherwise the transport layer can change
    /// the value.
    /// Read 4.4.3.8 Key information section of the https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf
    pub fn get_key_information(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0xDE)?;
        Some(tlv.v.clone())
    }

    /// Returns the name of the card holder.
    ///
    /// Name according to ISO/IEC 7501-1
    pub fn get_name(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0x5B)?;
        Some(tlv.v.clone())
    }

    /// Returns the bytes for the algorithm attritbutes of the Signature key
    pub fn get_signature_algo_attributes(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0xC1)?;
        Some(tlv.v.clone())
    }

    /// Returns the bytes for the algorithm attritbutes of the encryption key
    pub fn get_encryption_algo_attributes(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0xC2)?;
        Some(tlv.v.clone())
    }
    /// Returns the bytes for the algorithm attritbutes of the authentication key
    pub fn get_authentication_algo_attributes(&self) -> Option<Vec<u8>> {
        let tlv = self.find_tag(0xC3)?;
        Some(tlv.v.clone())
    }
}

/// Internal function to pop a u8 value from the front of the vector.
fn get(mut data: Vec<u8>) -> (u8, Vec<u8>) {
    let res: Vec<u8> = data.drain(0..1).collect();
    (res[0], data)
}

/// Utility function to convert any u8 or u16 to hex String
///
/// # Example
///
/// ```
/// println!(tlvs::hex(16));
/// ```
#[allow(unused)]
pub fn hex<T: UpperHex>(value: T) -> String {
    format!("0x{:X}", value)
}

/// Utility function to convert the TLV.v values into a string of hex.
///
/// # Example
///
/// ```
/// let t = big_box.find_tag(0xC1_u16).unwrap();
/// println!("This card's SIGN algo {}", tlvs::hexify(t.v));
/// ```
pub fn hexify(value: Vec<u8>) -> String {
    let mut res = String::new();
    for v in value.iter() {
        let hvalue = hex(v);
        res.push_str(" ");
        res.push_str(&hvalue);
    }
    res
}

// I am returning (TLV, Vec<u8>) as I still have to figure if any data left to be read
// and then read it for the next TLV.
/// Reads the given data and creates the TLV structure from the same. Also returns back any
/// extra data still remaining in the input. Used internally in the `read_list` function.
#[allow(unused_assignments)]
pub fn read_single(orig_data: Vec<u8>, recursive: bool) -> Result<(TLV, Vec<u8>), String> {
    let mut subs: Vec<TLV> = Vec::new();
    let data = orig_data.clone();
    let (t, mut data) = get(data);
    let mut t: u16 = (t & 0xff) as u16;
    let mut t2: u16 = 0;
    let composite: bool = (t & 0x20) == 0x20;
    if (t & 0x1f) == 0x1f {
        let p = get(data);
        t2 = p.0 as u16;
        data = p.1;
        t2 = t2 & 0xff;
        if (t2 & 0x1f) == 0x1f {
            return Err(String::from("Only two bytes for tags"));
        }
        let internal_t: u16 = t << 8;
        t = internal_t | (t2 & 0x7f);
    }

    //dbg!(hex(t));

    let p = get(data);
    let mut l: u16 = p.0 as u16;
    let mut data = p.1;
    if l == 0x81 {
        let p = get(data);
        l = p.0 as u16;
        data = p.1;
        l = l & 0xff;
    } else if l == 0x82 {
        let p = get(data);
        l = p.0 as u16;
        data = p.1;
        l = l & 0xff;
        let p = get(data);
        let second_l = p.0 as u16;
        data = p.1;
        let internal_l: u16 = l << 8_u8;
        l = internal_l | (second_l & 0xff);
    } else if l >= 0x80 {
        //dbg!("Inside of the error condition");
        //dbg!(hex(l));
        return Err(String::from("Invalid length field!"));
    }

    //dbg!(hex(l));
    let len: usize = l.clone() as usize;
    //let v = data.drain(0..len).collect();
    // If it is a composite, we need to pass the full value to the recursive call
    // else, we should consume the value from the data, and pass the rest.
    let v = if composite == true {
        data[..len].iter().cloned().collect()
    } else {
        data.drain(0..len).into_iter().collect()
    };

    // Look at the DO(s) which are marked as C in the section 4.4.1
    // of the OpenPGP-smart-card-application-3.4.1.pdf
    if recursive && composite {
        subs = read_list(data, true);
        return Ok((TLV { t, l, v, subs }, vec![]));
    }

    Ok((TLV { t, l, v, subs }, data))
}

/// This fundtion should be used to parse the data returned by the smartcard to convert them
/// into proper TLV structure.
///
/// # Example
///
/// ```
/// let mut f = File::open("./data/capabilities_tlv.binary").expect("no file found");
/// let mut buffer: Vec<u8> = Vec::new();
/// f.read_to_end(&mut buffer).unwrap();
/// let tlvs = read_list(buffer, true);
/// for bigb in big_box {
///     let ts = bigb.subs.clone();
///     for tlv in ts {
///         dbg!(tlvs::hex(tlv.t));
///         dbg!(tlvs::hex(tlv.l));
///         dbg!(tlv.if_recursive());
///     }
/// }
/// ```
///
pub fn read_list(orig_data: Vec<u8>, recursive: bool) -> Vec<TLV> {
    let mut result: Vec<TLV> = Vec::new();

    let mut data = orig_data.clone();
    while data.len() > 0 {
        if data[0] == 0xff || data[0] == 0x00 {
            // Then we skip the filler byte
            let p = get(data);
            data = p.1
        }
        // Now we can try to get a TLV
        let tmp = read_single(data, recursive).unwrap();
        data = tmp.1;
        result.push(tmp.0);
    }
    result
}

/// Returns 3 fingerprints as 3 elecment Vec<u8>, (signature, decryption, authentication).
pub fn parse_fingerprints(data: Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let sig_f = &data[0..20];
    let dec_f = &data[20..40];
    let auth_f = &data[40..60];
    return (
        sig_f.iter().cloned().collect(),
        dec_f.iter().cloned().collect(),
        auth_f.iter().cloned().collect(),
    );
}

/// Returns the serial number of the card from the AID response.
pub fn parse_card_serial(data: Vec<u8>) -> String {
    let mut res = String::new();
    for i in 10..14 {
        res.push_str(&format!("{:02X}", data[i]));
    }
    res
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::fs::File;
    use std::io::Read;
    fn get_my_tlv(filename: &str) -> TLV {
        let mut f = File::open(filename).expect("no file found");
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let big_box = &read_list(buffer, true)[0];
        big_box.clone()
    }
    // Helper function for tests
    fn read_file(filename: &str) -> Vec<u8> {
        let mut f = File::open(filename).expect("no file found");
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        return buffer;
    }

    #[test]
    fn test_create_tlv() {
        // This is the test data from a Yubikey.
        let mut f = File::open("./data/capabilities_tlv.binary").expect("no file found");
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let big_box = read_list(buffer, true);
        assert_eq!(big_box[0].get_t(), 0x006E);
        // TODO: fix the test to test the real values
        for bigb in big_box {
            let ts = bigb.subs.clone();
            for tlv in ts {
                dbg!(hex(tlv.t));
                dbg!(hex(tlv.l));
                dbg!(tlv.if_recursive());
            }
        }
    }

    #[test]
    fn test_parse_name_tlv() {
        let big_box = get_my_tlv("./data/name.binary");
        let tb = big_box.get_name().unwrap();
        assert_eq!(String::from_utf8(tb).unwrap(), String::from("Das<<Kushal"));
    }

    #[test]
    fn test_parse_fingerprints() {
        let hardcoded = (
            vec![
                11, 193, 53, 18, 94, 178, 255, 154, 15, 136, 238, 28, 198, 95, 240, 7, 199, 87,
                102, 237,
            ],
            vec![
                210, 186, 246, 33, 46, 76, 222, 84, 140, 51, 12, 61, 251, 130, 170, 93, 50, 109,
                167, 93,
            ],
            vec![
                98, 27, 19, 57, 205, 184, 49, 71, 154, 77, 235, 79, 124, 144, 242, 116, 158, 8, 94,
                29,
            ],
        );
        let big_box = get_my_tlv("./data/capabilities_tlv.binary");
        let tlv = big_box.get_fingerprints().unwrap();
        assert_eq!(hardcoded, parse_fingerprints(tlv));
    }

    #[test]
    fn test_parse_card_serial_number() {
        let data = read_file("./data/aid.binary");
        assert_eq!(parse_card_serial(data), "14490729");
    }
}
