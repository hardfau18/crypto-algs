#![feature(assert_matches)]
use core::assert_matches::assert_matches;
use crypto::vigenere as vig;

#[test]
fn enc_basic() {
    let msg = "This is a message";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    assert_eq!(v.enc(msg).unwrap(), "Vkmu#mu#e\"piuveih");
}

#[test]
fn dec_basic() {
    let crypt = "Vkmu#mu#e\"piuveih";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    assert_eq!(v.dec(crypt).unwrap(), "This is a message");
}

#[test]
fn duplex() {
    let msg = "This is a message";
    const KEY: [u8; 5] = [25, 52, 119, 9, 89];
    let v = vig::Vigenere::new(&KEY).unwrap();
    let cipher = v.enc(msg).unwrap();
    let decipher = v.dec(&cipher).unwrap();
    assert_eq!(msg, decipher);
}

#[test]
fn iter_enc() {
    let msg = "This is a message";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    let mut enc: vig::Encryptor = (&v, msg).into();
    assert_matches!(enc.next(), Some(Ok('V')));
    assert_matches!(enc.next(), Some(Ok('k')));
    assert_matches!(enc.next(), Some(Ok('m')));
    assert_matches!(enc.next(), Some(Ok('u')));
    assert_matches!(enc.next(), Some(Ok('#')));
    assert_matches!(enc.next(), Some(Ok('m')));
    assert_matches!(enc.next(), Some(Ok('u')));
    assert_matches!(enc.next(), Some(Ok('#')));
    assert_matches!(enc.next(), Some(Ok('e')));
    assert_matches!(enc.next(), Some(Ok('"')));
    assert_matches!(enc.next(), Some(Ok('p')));
    assert_matches!(enc.next(), Some(Ok('i')));
    assert_matches!(enc.next(), Some(Ok('u')));
    assert_matches!(enc.next(), Some(Ok('v')));
    assert_matches!(enc.next(), Some(Ok('e')));
    assert_matches!(enc.next(), Some(Ok('i')));
    assert_matches!(enc.next(), Some(Ok('h')));
    assert_matches!(enc.next(), None);
}

#[test]
fn iter_dec() {
    let crypt = "Vkmu#mu#e\"piuveih";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    let mut dec: vig::Decryptor = (&v, crypt).into();
    assert_matches!(dec.next(), Some(Ok('T')));
    assert_matches!(dec.next(), Some(Ok('h')));
    assert_matches!(dec.next(), Some(Ok('i')));
    assert_matches!(dec.next(), Some(Ok('s')));
    assert_matches!(dec.next(), Some(Ok(' ')));
    assert_matches!(dec.next(), Some(Ok('i')));
    assert_matches!(dec.next(), Some(Ok('s')));
    assert_matches!(dec.next(), Some(Ok(' ')));
    assert_matches!(dec.next(), Some(Ok('a')));
    assert_matches!(dec.next(), Some(Ok(' ')));
    assert_matches!(dec.next(), Some(Ok('m')));
    assert_matches!(dec.next(), Some(Ok('e')));
    assert_matches!(dec.next(), Some(Ok('s')));
    assert_matches!(dec.next(), Some(Ok('s')));
    assert_matches!(dec.next(), Some(Ok('a')));
    assert_matches!(dec.next(), Some(Ok('g')));
    assert_matches!(dec.next(), Some(Ok('e')));
    assert_matches!(dec.next(), None);
}

#[test]
fn invalid_char_enc() {
    let msg = "This is a message🧟";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    assert_matches!(v.enc(msg), Err(vig::InvalidCharError('🧟')));
}

#[test]
fn invalid_char_dec() {
    let cipher = "Vkmu#mu#e\"piuveih🧟";
    const KEY: [u8; 3] = [2, 3, 4];
    let v = vig::Vigenere::new(&KEY).unwrap();
    assert_matches!(v.dec(cipher), Err(vig::InvalidCharError('🧟')));
}

#[test]
fn invalid_key() {
    const KEY: [u8; 3] = [2, 255, 4];
    assert_matches!(vig::Vigenere::new(&KEY), Err(vig::InvalidKeyError::InvalidByte(255)));
}

#[test]
fn empty_key() {
    const KEY: [u8; 0] = [];
    assert_matches!(vig::Vigenere::new(&KEY), Err(vig::InvalidKeyError::EmptyKey));
}
