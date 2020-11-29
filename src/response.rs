//! Module to parse the response and makes sense of them.
//!

use crate::errors;

/// We can parse the output of `sendapdu` function into a `Response` structure. The first thing we
/// should check if the response `is_okay` or if there are more bytes watiting for us to read.
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct Response {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl Response {
    /// Creates a new `Response` structure.
    pub fn new(input: Vec<u8>) -> Result<Self, errors::TalktoSCError> {
        let length = input.len() as usize;
        if length < 2 {
            return Err(errors::TalktoSCError::ResponseError(length));
        }
        let data: Vec<u8>= Vec::from(&input[0..length  - 2]);
        let sw1 = input[length - 2];
        let sw2 = input[length - 1];
        Ok(Response { data, sw1, sw2 })
    }

    /// Tells if the response is okay (0x90 0x00) or not.
    pub fn is_okay(&self) -> bool {
        if self.sw1 == 0x90 && self.sw2 == 0x00 {
            return true
        } else {
            return false
        }
    }

    /// Returns a cloned copy of the data returned from card.
    pub fn get_data(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Returns Option<u8> to tell us how much bytes are still left to be read in the response.
    /// 0x61 LENGTH_TO_BE_READ are the values for sw1 and sw2.
    pub fn availble_response(&self) -> Option<u8> {
        match (self.sw1, self.sw2) {
            (0x61, value) => return Some(value),
            (_, _) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    #[test]
    fn test_two_bytes_data_response() {
        let res  = Response::new(vec![0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(res.is_okay(), true);
        assert_eq!(res.get_data(), vec![0x01, 0x02]);
    }
    #[test]
    fn test_no_data_response() {
        let res  = Response::new(vec![0x90, 0x00]).unwrap();
        assert_eq!(res.is_okay(), true);
        assert_eq!(res.get_data(), vec![]);
    }

    #[test]
    fn test_more_data_response() {
        let res  = Response::new(vec![0xAB, 0x61, 0x02]).unwrap();
        assert_eq!(res.is_okay(), false);
        assert_eq!(res.get_data(), vec![0xAB]);
        assert_eq!(res.availble_response().unwrap(), 2);
    }


}
