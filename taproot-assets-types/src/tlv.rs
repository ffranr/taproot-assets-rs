use alloc::{string::String, vec, vec::Vec};
use bitcoin::io::{self as bitcoin_io, Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Type(pub u64);

impl Type {
    pub fn is_odd(self) -> bool {
        self.0 % 2 != 0
    }
    pub fn is_even(self) -> bool {
        self.0 % 2 == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    tlv_type: Type,
    value: Vec<u8>,
}

impl Record {
    pub fn tlv_type(&self) -> Type {
        self.tlv_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn value_reader(&self) -> bitcoin_io::Cursor<&[u8]> {
        bitcoin_io::Cursor::new(&self.value)
    }
}

pub struct Stream<R: Read> {
    reader: R,
}

impl<R: Read> Stream<R> {
    pub fn new(reader: R) -> Self {
        Stream { reader }
    }

    fn read_u8_manual(&mut self) -> Result<u8, crate::error::Error> {
        let mut buf = [0; 1];
        self.reader
            .read_exact(&mut buf)
            .map_err(crate::error::Error::Io)?;
        Ok(buf[0])
    }

    fn read_u16_manual_be(&mut self) -> Result<u16, crate::error::Error> {
        let mut buf = [0; 2];
        self.reader
            .read_exact(&mut buf)
            .map_err(crate::error::Error::Io)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32_manual_be(&mut self) -> Result<u32, crate::error::Error> {
        let mut buf = [0; 4];
        self.reader
            .read_exact(&mut buf)
            .map_err(crate::error::Error::Io)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_u64_manual_be(&mut self) -> Result<u64, crate::error::Error> {
        let mut buf = [0; 8];
        self.reader
            .read_exact(&mut buf)
            .map_err(crate::error::Error::Io)?;
        Ok(u64::from_be_bytes(buf))
    }

    // Helper to read a var_int (compact size uin)
    fn read_var_int(&mut self) -> Result<u64, crate::error::Error> {
        let first_byte = self.read_u8_manual()?;
        match first_byte {
            0..=0xFC => Ok(first_byte as u64),
            0xFD => Ok(self.read_u16_manual_be()? as u64),
            0xFE => Ok(self.read_u32_manual_be()? as u64),
            0xFF => Ok(self.read_u64_manual_be()?),
        }
    }

    pub fn next_record(&mut self) -> Result<Option<Record>, String> {
        let tlv_type = match self.read_var_int() {
            Ok(val) => Type(val),
            Err(crate::error::Error::Io(_)) => return Ok(None), // Clean EOF or any I/O error when
            // starting to read a type.
            Err(e) => return Err(alloc::format!("Failed to read TLV type: {:?}", e)),
        };

        let length = match self.read_var_int() {
            Ok(val) => val,
            Err(e) => {
                return Err(alloc::format!(
                    "Failed to read TLV length for type {:?}: {:?}",
                    tlv_type,
                    e
                ))
            }
        };

        if length > (1_i32 << 20) as u64 {
            // Limit to ~1MB for safety
            return Err(alloc::format!(
                "TLV record too large: {} bytes for type {:?}",
                length,
                tlv_type
            ));
        }

        let mut value = vec![0; length as usize];
        match self.reader.read_exact(&mut value) {
            Ok(_) => Ok(Some(Record { tlv_type, value })),
            Err(e) => Err(alloc::format!(
                "Failed to read TLV value for type {:?} (length {}): {:?}",
                tlv_type,
                length,
                e
            )),
        }
    }
}

// Placeholder for a generic TLV decoder trait if needed later.
// pub trait Decoder: Sized {
//    fn decode<R: Read>(r: R) -> Result<Self, Error>;
// }

// Dummy Value type, not strictly needed if Record::value_reader() is used.
pub type Value<'a> = &'a [u8];
