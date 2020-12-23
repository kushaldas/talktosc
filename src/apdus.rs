//! Module apdus helps to create new APDUs. We have many `create_*` functions to help to create
//! predefined APDU structs.
//!

use std::fmt;

/// Creates APDU to be used inside of our project.
///
/// For now we have to use the raw u8 values to create a new APDU.
/// It automatically creates internal `ipapdus` vector with chained APDUs as required based on the
/// size of the data provided. Use [sendapdu](../fn.sendapdu.html) function to send an APDU to the
/// connected card.
#[derive(Clone)]
pub struct APDU {
    /// CLA information.
    pub cla: u8,
    /// INS value
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    /// Original `Vec<u8>` data which needs to send to the card.
    pub data: Vec<u8>,
    /// Chained APDUs in a vector. These are used internally in [sendapdu](../fn.sendapdu.html) function.
    pub iapdus: Vec<Vec<u8>>,
}

impl fmt::Debug for APDU {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut start = String::from("[");
        for iapdu in &self.iapdus {
            let mut resp = String::from("[");
            for value in iapdu {
                let hex = format!("0x{:X?}, ", value);
                resp.push_str(&hex[..]);
            }
            resp.push_str("]");
            start.push_str(&resp[..]);
        }
        start.push_str("]");
        f.debug_struct("APDU")
            .field("CLA", &self.cla)
            .field("INS", &self.ins)
            .field("P1", &self.p1)
            .field("P2", &self.p2)
            .field("ipapdus", &start)
            .finish()
    }
}

impl APDU {
    /// Creates a new APDU struct
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, inputdata: Option<Vec<u8>>) -> Self {
        let mut index = 1;
        let mut oindex = 0;
        let mut _cindex = 0;
        let data = match inputdata {
            Some(data) => data,
            None => vec![],
        };
        let length = data.len();
        let mut iapdus = Vec::new();
        while data.len() > index * 254 {
            _cindex = index * 254;
            let mut res = vec![0x10, ins, p1, p2, 254];
            res.extend(data[oindex.._cindex].iter().copied());
            iapdus.push(res);
            index += 1;
            oindex = _cindex;
        }
        let mut res = vec![cla, ins, p1, p2, (data.len() - oindex) as u8];
        res.extend(data[oindex..length].iter().copied());
        iapdus.push(res);
        APDU {
            cla,
            ins,
            p1,
            p2,
            data,
            iapdus,
        }
    }

    ///Create big APDU with >255 size, say to put the keys.
    pub fn create_big_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        let len = data.len() as u16;
        let mut iapdus = Vec::new();
        let mut res = vec![cla, ins, p1, p2];
        // If the lenght is bigger than 255, then 3 bytes size
        if len > 0xFF {
            let length = len.to_be_bytes();
            res.push(0x00);
            res.push(length[0]);
            res.push(length[1]);
        } else {
            let len = len as u8;
            res.push(len);
        }
        res.extend(data.iter());
        // We have only big APDU which we can send to the card
        iapdus.push(res);

        APDU {
            cla,
            ins,
            p1,
            p2,
            data,
            iapdus,
        }

    }
}
impl<'a> IntoIterator for &'a APDU {
    type Item = Vec<u8>;
    type IntoIter = APDUIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        APDUIterator {
            apdu: self,
            index: 0,
        }
    }
}

pub struct APDUIterator<'a> {
    apdu: &'a APDU,
    index: usize,
}
impl<'a> Iterator for APDUIterator<'a> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Vec<u8>> {
        if self.index < self.apdu.iapdus.len() {
            let res = self.apdu.iapdus[self.index].clone();
            self.index += 1;
            Some(res)
        } else {
            None
        }
    }
}

/// Creates a new APDU to select the OpenPGP applet in the card.
///
/// This is the **first** APDU to be sent to the card. Only after selecting
/// the OpenPGP applet, one should send in the other APDUs as required.
pub fn create_apdu_select_openpgp() -> APDU {
    APDU::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        Some(vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]),
    )
}

/// Creates a new APDU to fetch the public key URL from the card
pub fn create_apdu_get_url() -> APDU {
    APDU::new(0x00, 0xCA, 0x5F, 0x50, None)
}

/// Creates a new APDU to verify the PW1 for other commands. You should use this before trying to
/// decrypt any data.
pub fn create_apdu_verify_pw1_for_others(pin: Vec<u8>) -> APDU {
    APDU::new(0x00, 0x20, 0x00, 0x82, Some(pin))
}

/// Creates a new APDU to verify the PW1 for signing. You should use this before trying to
/// sign any data.
pub fn create_apdu_verify_pw1_for_sign(pin: Vec<u8>) -> APDU {
    APDU::new(0x00, 0x20, 0x00, 0x81, Some(pin))
}

/// Creates a new APDU to verify the PW3 for admin commands.
pub fn create_apdu_verify_pw3(pin: Vec<u8>) -> APDU {
    APDU::new(0x00, 0x20, 0x00, 0x83, Some(pin))
}

/// Creates a new APDU to select the personal information from the card.
pub fn create_apdu_personal_information() -> APDU {
    APDU::new(0x00, 0xCA, 0x00, 0x65, None)
}

/// Creates the APDU to get the AID (16 bytes) from the card.
/// See the table 4.2.1 in the SPEC 3.4.1 pdf
///
/// # Example
///
/// ```
/// let resp = sendapdu(&card, apdus::create_apdu_get_aid());
/// println!("Serial number: {}", tlvs::parse_card_serial(resp));
/// ```
pub fn create_apdu_get_aid() -> APDU {
    APDU::new(0x00, 0xCA, 0x00, 0x4F, None)
}

/// Creates a new APDU to get all the Application related data from the card
pub fn create_apdu_get_application_data() -> APDU {
    APDU::new(0x00, 0xCA, 0x00, 0x6E, None)
}

/// Creates new APDU for decryption operation
pub fn create_apdu_for_decryption(data: Vec<u8>) -> APDU {
    APDU::new(0x00, 0x2A, 0x80, 0x86, Some(data))
}

/// Creates new APDU only for reading more data from the card
///
/// Use this when the previous response is (0x61 length)
pub fn create_apdu_for_reading(length: u8) -> APDU {
    let cla = 0x00;
    let ins = 0xC0;
    let p1 = 0x00;
    let p2 = 0x00;
    let mut iapdus = Vec::new();
    let res = vec![0x00, 0xC0, 0x00, 0x00, length];
    iapdus.push(res);
    let data: Vec<u8> = Vec::new();
    APDU {
        cla,
        ins,
        p1,
        p2,
        data,
        iapdus,
    }
}

/// Creates big APDU to put algorithm attributes data in to the card
pub fn create_apdu_for_algo_attributes(data: Vec<u8>) -> APDU {
    APDU::create_big_apdu(0x00, 0xDA, 0x00, 0xC2, data)
}
