pub struct Des {
    _key: [u64; 16],
}
/// Genarates the round key for Key generation algorithm
struct KeyGen {
    /// lower 28 bits, top 4 bits must be ignored
    _lower_key: u32,
    /// upper 28 bits, top 4 bits must be ignored
    _upper_key: u32,
    /// iteration of the Keyscheduling algorithm
    _current_iteration: u8,
}

impl KeyGen {
    fn new(key: u64) -> Self {
        Self {
            _lower_key: (key & ((1 << 28) - 1)) as u32,
            _upper_key: ((key >> 28) & ((1 << 28) - 1)) as u32,
            _current_iteration: 0,
        }
    }
}

/// Permuted choice 1
/// this function scrambles the given key and generate 2 blocks 28 bit keys.
/// In every byte 8th bit is ignored since that bit is for parity
fn pc1(_key: u64) -> (u32, u32) {
    todo!()
}

/// Permuted choice 2
/// this function scrambles the given key and generates round key
/// key: 56 bit input key
/// return: 48 bit output key
fn pc2(_key: u64) -> u64 {
    todo!()
}

impl Iterator for KeyGen {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        todo!()
    }
}

impl ExactSizeIterator for KeyGen {
    fn len(&self) -> usize {
        self.size_hint().0
    }
}

impl cipher::BlockCipher for Des {}

impl cipher::BlockSizeUser for Des {
    type BlockSize = typenum::U8;
}
impl cipher::BlockEncrypt for Des {
    fn encrypt_with_backend(&self, _f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        todo!()
    }
}

impl cipher::KeySizeUser for Des {
    type KeySize = typenum::U8;
}

impl cipher::KeyInit for Des {
    fn new(key_bytes: &cipher::Key<Self>) -> Self {
        let key = u64::from_be_bytes(TryInto::<[u8; 8]>::try_into(key_bytes.as_slice()).unwrap());
        let mut key_gen = KeyGen::new(key);
        Self {
            _key: core::array::from_fn(|_| key_gen.next().unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn encrypt() {
        unimplemented!();
    }
}
