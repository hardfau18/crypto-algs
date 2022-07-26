#![feature(assert_matches)]
use core::assert_matches::assert_matches;
use crypto::transposition;
#[test]
fn encryt() {
    /*
     * 4    2   3   0   1
     * =====================
     * T    h   i   s
     * i    s       a
     * l    o   o   o   n
     * g        m   e   s
     * s    a   g   e   .
     * =====================
     * cipher = "saoee  ns.hso ai omgTilgs"
     */
    let msg = "This is a looong message.";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.enc(msg).unwrap(), "saoee  ns.hso ai omgTilgs");
}

#[test]
fn decrypt() {
    /*
     * cipher = "saoee  ns.hso ai omgTilgs"
     * <-(msg/block size) ->
     * =============================
     *  s   a   o   e   e
     *          n   s   .
     *  h   s   o       a
     *  i       o   m   g
     *  T   i   l   g   s
     *  =============================
     */
    let cipher = "saoee  ns.hso ai omgTilgs";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.dec(cipher).unwrap(), "This is a looong message.");
}
#[test]
fn enc_with_emoji() {
    let msg = "This is a looong message🤩";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.enc(msg).unwrap(), "saoee  ns🤩hso ai omgTilgs");
}
#[test]
fn dec_with_emoji() {
    let cipher = "saoee  ns🤩hso ai omgTilgs";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.dec(cipher).unwrap(), "This is a looong message🤩");
}
#[test]
fn enc_with_irregular_size() {
    let msg = "This is a looong message";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert!(!matches!(
        trans.enc(msg),
        Err(transposition::IncorrectSize(1))
    ));
}
#[test]
fn dec_with_irregular_size() {
    let cipher = "saoee  nshso ai omgTilgs";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert!(!matches!(
        trans.dec(cipher),
        Err(transposition::IncorrectSize(1))
    ));
}

#[test]
fn full_dup() {
    let msg = "This is a looong message.";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    let cipher = trans.enc(msg).unwrap();
    assert_eq!(trans.dec(&cipher).unwrap(), msg);
}

#[test]
fn missing_key() {
    const KEY: [u8; 5] = [3, 5, 2, 4, 1];
    assert_matches!(
        transposition::Transposition::new(&KEY),
        Err(transposition::KeyError::MissingKey(0))
    );
}

#[test]
fn dup_key() {
    const KEY: [u8; 5] = [3, 2, 2, 4, 0];
    assert_matches!(
        transposition::Transposition::new(&KEY),
        Err(transposition::KeyError::DuplicateKey(2))
    );
}

#[test]
fn empty_msg() {
    let msg = "";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.enc(msg).unwrap(), "");
}

#[test]
fn empty_cipher() {
    let cipher = "";
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    assert_eq!(trans.dec(cipher).unwrap(), "");
}
