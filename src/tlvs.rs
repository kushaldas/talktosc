//! This module implements ISO7816 TLV format.
//!

pub trait ISO7816TLV {
    fn get_t(&self) -> u8;
    fn get_l(&self) -> u8;
    fn get_v(&self) -> &[u8];
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct TLV {
    pub t: u8,
    pub l: u8,
    pub v: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RTLV {
    pub t: u8,
    pub l: u8,
    pub v: Vec<u8>,
    pub subs: Vec<TLV>,
}

impl ISO7816TLV for TLV {
    fn get_t(&self) -> u8 {
        self.t
    }
    fn get_l(&self) -> u8 {
        self.l
    }
    fn get_v(&self) -> &[u8] {
        &self.v[..]
    }
}

impl ISO7816TLV for RTLV {
    fn get_t(&self) -> u8 {
        self.t
    }
    fn get_l(&self) -> u8 {
        self.l
    }
    fn get_v(&self) -> &[u8] {
        &self.v[..]
    }
}

fn get(mut data: Vec<u8>) -> (u8, Vec<u8>) {
    let res: Vec<u8> = data.drain(0..1).collect();
    (res[0], data)
}

#[allow(unused_assignments)]
impl TLV {
    pub fn read_single(orig_data: Vec<u8>, recursive: bool) -> Result<Box<dyn ISO7816TLV>, String> {
        let data = orig_data.clone();
        let (t, mut data) = get(data);
        let mut t = t & 0xff;
        let mut t2: u8 = 0;
        let composite: bool = (t & 0x20) == 0x20;
        if (t & 0x1f) == 0x1f {
            let p = get(data);
            t2 = p.0;
            data = p.1;
            t2 = t2 & 0xff;
            if (t2 & 0x1f) == 0x1f {
                return Err(String::from("Only two bytes for tags"));
            }
            let (internal_t, _) = t.overflowing_shl(8);
            t = internal_t | (t2 & 0x7f);
        }

        let (mut l, mut data) = get(data);
        if l == 0x81 {
            let p = get(data);
            l = p.0;
            data = p.1;
            l = l & 0xff;
        } else if l == 0x82 {
            let p = get(data);
            l = p.0;
            data = p.1;
            l = l & 0xff;
            let p = get(data);
            let second_l = p.0;
            data = p.1;
            let (internal_l, _) = l.overflowing_shl(8);
            l = internal_l | (second_l & 0xff);
        } else if l >= 0x80 {
            return Err(String::from("Invalid length field!"));
        }

        let len: usize = l.clone() as usize;
        let v = data.drain(0..len).collect();

        // TODO: Parse composite here.
        //
        //
        Ok(Box::new(TLV { t, l, v }))
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::fs::File;
    use std::io::Read;
    #[test]
    fn test_create_tlv() {
        let mut f = File::open("./data/capabilities_tlv.binary").expect("no file found");
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        let tlv_in_box = TLV::read_single(buffer, false).unwrap();
        println!("Tag: {:X}", tlv_in_box.get_t());
    }
}
