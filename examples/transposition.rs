use crypto::transposition;
fn main() {
    let msg = "Finally🤩🤩🤩, some cipher which works with emojis😌😌😌";
    println!("Messasge: {msg}");
    const KEY: [u8; 5] = [4, 2, 3, 0, 1];
    let trans = transposition::Transposition::new(&KEY).unwrap();
    let cipher = trans.enc(msg).unwrap();
    println!("Cipher: {cipher}");
    let decipher = trans.dec(&cipher).unwrap();
    println!("Decipher: {decipher}");
}
