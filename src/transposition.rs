//! In Transposition cipher msg is devided into blocks of given key size then from that block characters are serialize in the order specified in key.
//! But this is vulnerable to anagram attacks.
//! Column Transposition cipher in which msg is written in matrix form with column count equal to key len.
//! Then cipher is generate by reading matrix in columnwise manner and the column is choose in order specified in key

/// Column Transposition cipher
#[derive(Debug)]
pub struct Transposition {
    key: Vec<u8>,
    block_size: usize,
}

/// Incorrect cipher/message size,
/// cipher/message len should be multiple of block_size(key len)
#[derive(Debug)]
pub struct IncorrectSize(pub usize);

/// Error enum for key verification
#[derive(Debug)]
pub enum KeyError {
    /// duplicate key in keyarray
    DuplicateKey(u8),
    /// missing key, key array should contain all the numbers from 0-keylen(exclusize)
    MissingKey(u8),
}
impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateKey(k) => write!(f, "duplicate key {}", k),
            Self::MissingKey(k) => write!(f, "missing key {}", k),
        }
    }
}

impl std::error::Error for KeyError {}

impl Transposition {
    /// key_ref should contain a array of numbers starting from 0 and it all numbers should be present and not  and not duplicated
    pub fn new(key_ref: &[u8]) -> Result<Self, KeyError> {
        let mut key = Vec::with_capacity(key_ref.len());
        for k in key_ref {
            if key.iter().any(|x| *x == *k) {
                return Err(KeyError::DuplicateKey(*k));
            }
            key.push(*k);
        }
        for i in 0..(key.len() as u8) {
            if !key.iter().any(|&x| x == i) {
                return Err(KeyError::MissingKey(i as u8));
            }
        }
        let block_size = key.len();
        Ok(Self { key, block_size })
    }
    /// encrypts the given string. characters are not limited to ascii in this case, null character(\0) should be avoided since they are used for padding
    pub fn enc(&self, msg: &str) -> Result<String, IncorrectSize> {
        let msg_len_miss = msg.chars().count() % self.block_size;
        if msg_len_miss % self.block_size != 0 {
            return Err(IncorrectSize(msg_len_miss));
        };
        let mut grp = vec![String::new(); self.key.len()];
        msg.chars().enumerate().for_each(|(indx, chr)| {
            unsafe {
                grp.get_unchecked_mut(*self.key.get_unchecked(indx % self.block_size) as usize)
                    .push(chr)
            };
        });
        Ok(grp.join(""))
    }
    /// decrypts the given cipher.
    /// If the given cipher has NULL character padding then it should be popped by user.
    pub fn dec(&self, cipher: &str) -> Result<String, IncorrectSize> {
        //  NOTE: This O(n) operation this can slow down
        let cipher_len = cipher.chars().count();
        // cipher = "saoee  ns.hso ai omgTilgs"
        // <-(msg/block size) ->
        // =============================
        //  s   a   o   e   e
        //          n   s   .
        //  h   s   o       a
        //  i       o   m   g
        //  T   i   l   g   s
        //  =============================
        //  pop in the order of key index
        if cipher_len % self.block_size != 0 {
            return Err(IncorrectSize(cipher_len % self.block_size));
        }
        let tank_vol = cipher_len / self.block_size;
        let mut tanks = Vec::with_capacity(self.block_size);
        let mut msg = String::with_capacity(cipher_len);
        (0..self.block_size).for_each(|idx| tanks.push(cipher.chars().skip(idx * tank_vol)));
        (0..tank_vol).for_each(|_| {
            (0..self.block_size)
                .for_each(|tank_idx| msg.push(tanks[self.key[tank_idx] as usize].next().unwrap()))
        });
        Ok(msg)
    }
}
