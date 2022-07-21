#![feature(assert_matches)]
use core::assert_matches::assert_matches;
use crypto::*;

#[test]
fn shift_basic() {
    let msg = "This is a non-secret message";
    const KEY: u8 = 23;
    let c = shift::enc(msg, KEY).unwrap();
    let dec_msg = shift::dec(&c, KEY).unwrap();
    assert_eq!(dec_msg, msg);
}

#[test]
fn shift_inv_enc_key() {
    let msg = "This is a non-secret message";
    const KEY: u8 = 132;
    assert_matches!(shift::enc(msg, KEY), Err(shift::Error::InvalidKey));
}
#[test]
fn invalid_msg_char() {
    let msg = "This is a non-secret message 💣";
    const KEY: u8 = 45;
    assert_matches!(shift::enc(msg, KEY), Err(shift::Error::InvalidByte('💣')));
}
