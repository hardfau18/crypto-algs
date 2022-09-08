/// Data Encryption Standard
/// A Block cipher which works on 64 bit blocks of data
pub struct Des {
    _key: Key,
}

// public functions
impl Des {
    /// creates a Des cipher block with given 64 bit key
    pub fn new(_key: u64) -> Self {
        todo!()
    }
    /// encrypts the given 64 bit msg and gives 64 bit cipher text
    pub fn encrypt(&self, _msg: u64) -> u64 {
        todo!()
    }
    /// decrypts the given 64 bit cipher and gives 64 bit msg
    pub fn decrypt(&self, _msg: u64) -> u64 {
        todo!()
    }
    /// encrypts all the bytes from a given array and copied into cipher array
    /// NOTE: both cipher and msg should have same len
    pub fn encrypt_all(&self, _msg: &[u8], _cipher: &mut [u8]) {}
    /// decrypts all the bytes from a given array
    /// NOTE: both cipher and msg should have same len
    pub fn decrypt_all(&self, _cipher: &[u8], _msg: &mut [u8]) {}
}
// private impls
impl Des {
    /// Initail Permutation Table, 0 means 0th bit, it is little endian, 64 means MSB
    /// ie. MSB of the ouptut will be 6th bit(from lsb), and lsb of the output will the 57th bit(from LSB)
    const IP_TABLE: [u8; 64] = [
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    ];
    /// Final Permutation Table
    const FP_TABLE: [u8; 64] = [
        39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61,
        29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18,
        58, 26, 33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
    ];

    /// Expansion Table
    const E_TABLE: [u8; 48] = [
        31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16,
        17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
    ];

    /// Perrmutation Table
    const P_TABLE: [u8; 32] = [
        7, 28, 21, 10, 26, 2, 19, 13, 23, 29, 5, 0, 18, 8, 24, 30, 22, 1, 14, 27, 6, 9, 17, 31, 15,
        4, 20, 3, 11, 12, 25, 16,
    ];

    /// Permutation Choice 1 left table, left 28 bit key halve is generated
    const PC1_L_TABLE: [u8; 28] = [
        28, 20, 12, 4, 61, 53, 45, 37, 29, 21, 13, 5, 62, 54, 46, 38, 30, 22, 14, 6, 63, 55, 47,
        39, 31, 23, 15, 7,
    ];
    /// Permutation Choice 1 right table, right 28 bit key halve is generated
    const PC1_R_TABLE: [u8; 28] = [
        60, 52, 44, 36, 59, 51, 43, 35, 27, 19, 11, 3, 58, 50, 42, 34, 26, 18, 10, 2, 57, 49, 41,
        33, 25, 17, 9, 1,
    ];

    /// Permutation choice 2 Table, 48 bit key is generated from 64 bit key
    const PC2_TABLE: [u8; 48] = [
        32, 35, 28, 14, 22, 18, 11, 30, 8, 25, 15, 20, 16, 31, 19, 13, 24, 34, 9, 17, 27, 33, 12,
        23, 62, 51, 44, 37, 57, 48, 56, 38, 60, 52, 45, 41, 54, 43, 58, 49, 36, 61, 59, 63, 40, 53,
        47, 50,
    ];
    /// applies  initial permutation(IP) on message
    fn _ip(msg: u64) -> u64 {
        let mut op: u64 = 0;
        Self::IP_TABLE.iter().enumerate().for_each(|(i, bit_pos)| {
            // if the bit in the bit_position is set then, set the  bit in the corresponding index
            if (1 << bit_pos) & msg != 0 {
                op |= 1 << i;
            }
        });
        op
    }
    /// applies  initial permutation(IP) on message
    fn _fp(msg: u64) -> u64 {
        let mut op: u64 = 0;
        Self::FP_TABLE.iter().enumerate().for_each(|(i, bit_pos)| {
            // if the bit in the bit_position is set then, set the  bit in the corresponding index
            if (1 << bit_pos) & msg != 0 {
                op |= 1 << i;
            }
        });
        op
    }
    /// takes 2 halves 32 bit halves of message with 48 bit key and applies feistel function on it
    fn _fiestel_box(_msg: (u32, u32), _key: u64) -> (u32, u32) {
        todo!()
    }
    /// Substitution box, takes 48 bit message and returns 32 bit halve
    fn _s_box(_msg: u64) -> u32 {
        todo!()
    }
    /// Permutation box, applies permutation on 32 bit message
    fn _p_box(_msg: u32) -> u32 {
        todo!()
    }
    /// Expantion box, takes 32 bit message and expands it to 48 bit
    fn _e_box(_msg: u32) -> u64 {
        todo!()
    }
}

/// key for DES algorithm, it contains generated key with keyscheduling algorithm
pub struct Key {
    _key: u64,
    _expanded_key: [u64; 16],
}

impl Key {
    const _SHIFT_ARR: [u8; 16] = [0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0];
    /// creates a key and expands it to 16 rounds
    fn _new(_key: u64) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_fp() {
        let msg: u64 = 18293334370779143615;
        assert_eq!(Des::_fp(Des::_ip(msg)), msg);
    }
}
