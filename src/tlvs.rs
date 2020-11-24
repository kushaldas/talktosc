//! This module implements ISO7816 TLV format.
//!

use std::fmt::UpperHex;

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
}

/// Internal function to pop a u8 value from the front of the vector.
fn get(mut data: Vec<u8>) -> (u8, Vec<u8>) {
    let res: Vec<u8> = data.drain(0..1).collect();
    (res[0], data)
}

/// Utility function to convert any u8 or u16 to hex String
#[allow(unused)]
pub fn hex<T: UpperHex>(value: T) -> String {
    format!("0x{:X}", value)
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

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::fs::File;
    use std::io::Read;
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
}
