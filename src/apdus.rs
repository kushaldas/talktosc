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

/// Creates a new APDU to select the personal information from the card.
pub fn create_apdu_personal_information() -> APDU {
    APDU::new(0x00, 0xCA, 0x00, 0x65, None)
}
