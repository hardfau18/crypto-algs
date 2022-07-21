use crypto::*;
fn main() {
    let message = "This is normal message";
    const KEY: u8 = 80;
    let c = shift::enc(message, KEY).unwrap();
    let d = shift::dec(&c, KEY).unwrap();
    println!("Enc({message}) = {c}");
    println!("Dec({c}) = {d}");
}
