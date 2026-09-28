//! Minecraft primitive reader/writer with strict limits (vanilla behavior).

use crate::error::McError;

pub const MAX_VARINT_BYTES: usize = 5;

pub struct Writer {
    pub out: Vec<u8>,
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Writer {
    pub fn new() -> Self {
        Writer { out: Vec::with_capacity(64) }
    }

    pub fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    pub fn i8(&mut self, v: i8) {
        self.out.push(v as u8);
    }

    pub fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i16(&mut self, v: i16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    pub fn boolean(&mut self, v: bool) {
        self.out.push(if v { 1 } else { 0 });
    }

    pub fn varint(&mut self, mut v: u32) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            self.out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    /// Minecraft String: VarInt length prefix + UTF-8 bytes.
    pub fn string(&mut self, s: &str) {
        let b = s.as_bytes();
        assert!(b.len() <= 32767, "string too long for wire format");
        self.varint(b.len() as u32);
        self.out.extend_from_slice(b);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    /// Short-prefixed byte array (used by login encryption packets in 1.8).
    pub fn array_short(&mut self, b: &[u8]) {
        assert!(b.len() <= u16::MAX as usize, "array too long for wire format");
        self.u16(b.len() as u16);
        self.out.extend_from_slice(b);
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Fail if the packet body was not consumed exactly (vanilla kicks on trailing bytes).
    pub fn assert_end(&self) -> crate::error::McResult<()> {
        if self.remaining() > 0 {
            return Err(McError::new("packet has trailing bytes"));
        }
        Ok(())
    }

    fn need(&self, n: usize) -> crate::error::McResult<()> {
        if self.remaining() < n {
            Err(McError::new("packet underflow"))
        } else {
            Ok(())
        }
    }

    pub fn u8(&mut self) -> crate::error::McResult<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn i8(&mut self) -> crate::error::McResult<i8> {
        Ok(self.u8()? as i8)
    }

    pub fn u16(&mut self) -> crate::error::McResult<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn i16(&mut self) -> crate::error::McResult<i16> {
        Ok(self.u16()? as i16)
    }

    pub fn u32(&mut self) -> crate::error::McResult<u32> {
        self.need(4)?;
        let s = &self.data[self.pos..self.pos + 4];
        self.pos += 4;
        Ok(u32::from_be_bytes(s.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> crate::error::McResult<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> crate::error::McResult<u64> {
        self.need(8)?;
        let s = &self.data[self.pos..self.pos + 8];
        self.pos += 8;
        Ok(u64::from_be_bytes(s.try_into().unwrap()))
    }

    pub fn i64(&mut self) -> crate::error::McResult<i64> {
        Ok(self.u64()? as i64)
    }

    pub fn boolean(&mut self) -> crate::error::McResult<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(McError::new(format!("invalid boolean byte {other}"))),
        }
    }

    pub fn varint(&mut self) -> crate::error::McResult<u32> {
        self.varint_capped(MAX_VARINT_BYTES)
            .map_err(|_| McError::new("VarInt too big"))
    }

    fn varint_capped(&mut self, max_bytes: usize) -> Result<u32, ()> {
        let mut result: u32 = 0;
        for i in 0..max_bytes {
            if self.pos >= self.data.len() {
                return Err(());
            }
            let b = self.data[self.pos];
            self.pos += 1;
            result |= ((b & 0x7F) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(())
    }

    /// String with vanilla cap semantics: byte length <= max*4.
    pub fn string(&mut self, max_chars: usize) -> crate::error::McResult<String> {
        let len = self.varint()? as usize;
        if len > max_chars.saturating_mul(4) {
            return Err(McError::new("string too long"));
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| McError::new("invalid UTF-8 in string"))
    }

    pub fn take(&mut self, n: usize) -> crate::error::McResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Remaining bytes (used by custom payload data).
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }

    /// Short-prefixed byte array (login encryption packets in 1.8).
    pub fn array_short(&mut self, max: usize) -> crate::error::McResult<Vec<u8>> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(McError::new("array too long"));
        }
        Ok(self.take(len)?.to_vec())
    }
}

pub fn varint_size(mut v: u32) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u32, 1, 127, 128, 255, 4095, 2097151, 268435455] {
            let mut w = Writer::new();
            w.varint(v);
            let mut r = Reader::new(&w.out);
            assert_eq!(r.varint().unwrap(), v);
            r.assert_end().unwrap();
        }
    }

    #[test]
    fn varint_too_big() {
        // 6 continuation bytes: wider than 5-byte VarInt.
        let bad = [0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        let mut r = Reader::new(&bad);
        assert!(r.varint().is_err());
    }

    #[test]
    fn varint_known_bytes() {
        let mut w = Writer::new();
        w.varint(0);
        assert_eq!(w.out, [0x00]);
        w.out.clear();
        w.varint(127);
        assert_eq!(w.out, [0x7F]);
        w.out.clear();
        w.varint(128);
        assert_eq!(w.out, [0x80, 0x01]);
        w.out.clear();
        w.varint(2097151);
        assert_eq!(w.out, [0xFF, 0xFF, 0x7F]);
    }
}
