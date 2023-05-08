

use xplugins_crypto;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();    

    let filename = args[1].clone();
    let signed_file = false;

    let gfile = xplugins_crypto::g64::G64File::from_file(&filename, signed_file).unwrap();

    let password = "good-luck-cracking-rsa-sigs-you-pathetic-idiots";

    let plain_text = gfile.decrypt(password).unwrap();
    println!("plain_text:\n{}", String::from_utf8(plain_text).expect("Invalid UTF-8"));


}