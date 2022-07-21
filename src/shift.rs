//! This is implementation of shift cipher, where encryption function is to do a wrapping add a key to character.
//! NOTE: This is unsafe due to very small key & cipher text space
#[derive(Debug)]
pub enum Error {
    InvalidKey,
    InvalidByte(char),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "InvalidKey"),
            Error::InvalidByte(b) => write!(f, "Invalid character byte recieved {b}"),
        }
    }
}
impl std::error::Error for Error {}

/// does shift cipher encryption of the given string and returns result, if string contains non ascii characters then retuns Error
/// This is not limited to 26 characters 0-127 ascii characters are supported
/// `key` should be 0-127 only else error is returned
pub fn enc(msg: &str, key: u8) -> Result<String, Error> {
    if key > 127 {
        return Err(Error::InvalidKey);
    }
    let mut c = String::new();
    for chr in msg.chars() {
        if !chr.is_ascii() {
            return Err(Error::InvalidByte(chr));
        };
        // SAFETY: since result of module will always be within 0-127 output will be valid character
        c.push(unsafe { char::from_u32_unchecked(((chr as u8 + key) % 128).into()) })
    }
    Ok(c)
}

/// does shift cipher decryption of the given string slice and returns result, if string contains non ascii characters then retuns Error
/// `key` should be 0-127 only else error is returned
pub fn dec(crypt: &str, key: u8) -> Result<String, Error> {
    if key > 127 {
        return Err(Error::InvalidKey);
    }
    let mut msg = String::new();
    for chr in crypt.chars() {
        if !chr.is_ascii() {
            return Err(Error::InvalidByte(chr));
        };
        // SAFETY: since result of module will always be within 0-127 output will be valid character
        msg.push(unsafe {
            char::from_u32_unchecked((((chr as u8).wrapping_sub(key)) % 128).into())
        })
    }
    Ok(msg)
}
