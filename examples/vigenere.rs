use crypto::vigenere;
fn main() {
    let msg = "This is normal message";
    const KEY: [u8; 5] = [25, 52, 119, 9, 89];
    let v = vigenere::Vigenere::new(&KEY).unwrap();
    let cipher = v.enc(msg).unwrap();
    let decipher = v.dec(&cipher).unwrap();
    println!("Enc({msg}) = {cipher}");
    println!("Dec({cipher}) = {decipher}");
}
