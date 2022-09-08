use crypto::des;

#[test]
fn encrypt_block() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let msg = u64::from_be_bytes([0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13]);
    let cipher = u64::from_be_bytes([0x58, 0x1f, 0x17, 0xd8, 0x95, 0xea, 0x4b, 0x4a]);
    assert_eq!(alg.encrypt(msg), cipher);
}

#[test]
fn decrypt_block() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let msg = u64::from_be_bytes([0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13]);
    let cipher = u64::from_be_bytes([0x58, 0x1f, 0x17, 0xd8, 0x95, 0xea, 0x4b, 0x4a]);
    assert_eq!(alg.decrypt(cipher), msg);
}

#[test]
fn full_duplex_block() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let ref_msg = u64::from_be_bytes([0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13]);
    let ref_cipher = u64::from_be_bytes([0x58, 0x1f, 0x17, 0xd8, 0x95, 0xea, 0x4b, 0x4a]);
    let cipher: u64 = alg.encrypt(ref_msg);
    let msg: u64 = alg.decrypt(cipher);
    assert_eq!(cipher, ref_cipher);
    assert_eq!(msg, ref_msg);
}

#[test]
fn encrypt_bytes() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let msg = &[todo!()];
    let cipher = &mut [todo!()];
    alg.encrypt_all(msg, cipher);
    assert_eq!(cipher, &[todo!()]);
}

#[test]
fn decrypt_bytes() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let cipher = &[todo!()];
    let msg = &mut [todo!()];
    alg.decrypt_all(cipher, msg);
    assert_eq!(msg, &[todo!()]);
}

#[test]
fn full_duplex_bytes() {
    let alg = des::Des::new(u64::from_be_bytes([
        0xa2, 0x23, 0x49, 0x94, 0x32, 0xd3, 0xf2, 0x13,
    ]));
    let cipher = &mut [todo!()];
    let ref_cipher = &[todo!()];
    let msg = &mut [todo!()];
    let ref_msg = &[todo!()];
    alg.encrypt_all(msg, cipher);
    alg.decrypt_all(cipher, msg);
    assert_eq!(msg, ref_msg);
    assert_eq!(cipher, ref_cipher);
}
