//! Its an implementation of vigenere cipher.
//! vigenere cipher is poly alphabetic cipher(there is no one to one mapping between cipher text and message)
//! vigenere cipher is a variant of shift cipher, in this message is devided into blocks of size m.
//! Key will be an array of size m and each character from message block will be shifted by a value with respect key from key space.

/// Passed key is invalid, and contains invalid byte from key
#[derive(Debug)]
pub enum InvalidKeyError {
    InvalidByte(u8),
    EmptyKey,
}
/// passed cipher or message has non ascii  character
#[derive(Debug)]
pub struct InvalidCharError(pub char);

impl std::fmt::Display for InvalidKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidKeyError::InvalidByte(byte) => write!(f, "InvalidKey {}", byte),
            InvalidKeyError::EmptyKey => write!(f, "Empty key"),
        }
    }
}

impl std::fmt::Display for InvalidCharError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InvalidCharacter {}", self.0)
    }
}

impl std::error::Error for InvalidKeyError {}
impl std::error::Error for InvalidCharError {}

/// This struct can be used to encrypt or decrypt a str
#[derive(Debug)]
pub struct Vigenere<'a> {
    key: &'a [u8],
}

impl<'a> Vigenere<'a> {
    /// verifies the key, if key is invalid then it returns invalidkey error
    pub fn new(key: &'a [u8]) -> Result<Self, InvalidKeyError> {
        if key.is_empty() {
            return Err(InvalidKeyError::EmptyKey);
        }
        if let Some(inval_key) = key.iter().find(|k| **k > 127) {
            return Err(InvalidKeyError::InvalidByte(*inval_key));
        }
        Ok(Self { key })
    }
    /// encrypts msg using key provided in new method,
    /// msg should be ascii characters only.
    /// Output will be ascii characters.
    /// Returns Invalid Byte if the given string contains non ascii characters
    pub fn enc(&self, msg: &str) -> Result<String, InvalidCharError> {
        let mut res = String::new();
        let mut idx = 0;
        for chr in msg.chars() {
            if !chr.is_ascii() {
                return Err(InvalidCharError(chr));
            }
            // SAFETY
            // Since we know that %128 will give valid ascii character(yes even NULL is also valid character) we can safely typecast it.
            res.push(unsafe {
                char::from_u32_unchecked(((chr as u8 + self.key[idx]) % 128).into())
            }); // since key is nonempty it is safe to index.
            idx = (idx + 1) % self.key.len();
        }
        Ok(res)
    }
    /// decrypts msg using key provided in new method,
    /// cipher should be ascii characters only.
    /// Returns Invalid Byte if the given string contains non ascii characters
    pub fn dec(&self, cipher: &str) -> Result<String, InvalidCharError> {
        let mut res = String::new();
        let mut idx = 0;
        for chr in cipher.chars() {
            if !chr.is_ascii() {
                return Err(InvalidCharError(chr));
            }
            // SAFETY
            // Since we know that %128 will give valid ascii character(yes even NULL is also valid character) we can safely typecast it.
            res.push(unsafe {
                char::from_u32_unchecked((((chr as u8).wrapping_sub(self.key[idx])) % 128).into())
            }); // since key is nonempty it is safe to index.
            idx = (idx + 1) % self.key.len();
        }
        Ok(res)
    }
}

pub struct Encryptor<'a, 'b> {
    msg: std::str::Chars<'b>,
    key: &'b Vigenere<'a>,
    pos: usize,
}

pub struct Decryptor<'a, 'b> {
    msg: std::str::Chars<'b>,
    key: &'b Vigenere<'a>,
    pos: usize,
}

impl Iterator for Encryptor<'_, '_> {
    type Item = Result<char, InvalidCharError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(chr) = self.msg.next() {
            if !chr.is_ascii() {
                return Some(Err(InvalidCharError(chr)));
            }
            // SAFETY
            // Since we know that %128 will give valid ascii character(yes even NULL is also valid character) we can safely typecast it.
            let enc_char = unsafe {
                char::from_u32_unchecked(((chr as u8 + self.key.key[self.pos]) % 128).into())
            }; // since key is nonempty it is safe to index.
            self.pos = (self.pos + 1) % self.key.key.len();
            Some(Ok(enc_char))
        } else {
            None
        }
    }
}
impl Iterator for Decryptor<'_, '_> {
    type Item = Result<char, InvalidCharError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(chr) = self.msg.next() {
            if !chr.is_ascii() {
                return Some(Err(InvalidCharError(chr)));
            }
            // SAFETY
            // Since we know that %128 will give valid ascii character(yes even NULL is also valid character) we can safely typecast it.
            let enc_char = unsafe {
                char::from_u32_unchecked(
                    (((chr as u8).wrapping_sub(self.key.key[self.pos])) % 128).into(),
                )
            }; // since key is nonempty it is safe to index.
            self.pos = (self.pos + 1) % self.key.key.len();
            Some(Ok(enc_char))
        } else {
            None
        }
    }
}

impl<'a, 'b> From<(&'b Vigenere<'a>, &'b str)> for Encryptor<'a, 'b> {
    fn from((v, msg): (&'b Vigenere<'a>, &'b str)) -> Self {
        Self {
            msg: msg.chars(),
            key: v,
            pos: 0,
        }
    }
}

impl<'a, 'b> From<(&'b Vigenere<'a>, &'b str)> for Decryptor<'a, 'b> {
    fn from((v, msg): (&'b Vigenere<'a>, &'b str)) -> Self {
        Self {
            msg: msg.chars(),
            key: v,
            pos: 0,
        }
    }
}
