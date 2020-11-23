use pcsc::*;
use std::fmt;
use std::str;

pub fn create_connection() -> Option<Card> {
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

pub fn sendapdu(card: &Card, apdu: APDU) -> Vec<u8> {
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

/// Creates APDU to be used inside of our project.
///
/// For now we have to use the raw u8 values to create a new APDU.
#[derive(Clone)]
pub struct APDU {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    iapdus: Vec<Vec<u8>>,
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

pub fn entry() {
    let card = create_connection().unwrap();
    //let select_openpgp: [u8; 11] = [0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
    let select_openpgp = APDU::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        Some(vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]),
    );

    let resp = sendapdu(&card, select_openpgp);
    println!("Received Final: {:x?}", resp);
    let get_url_apdu = APDU::new(0x00, 0xCA, 0x5F, 0x50, None);
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
