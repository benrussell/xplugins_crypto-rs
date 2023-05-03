
use xplugins_crypto::{self, g64::DecryptOptions};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();    
    
    let decrypt_options = DecryptOptions{
        filename: args[1].clone(),
        password: "good-luck-cracking-rsa-sigs-you-pathetic-idiots".to_string(),
        signed_file: true,
    };

    let plain_text = xplugins_crypto::g64::decrypt_file(decrypt_options).expect("Decrypt Failed");

    println!("plain_text:\n{}", String::from_utf8(plain_text).expect("Invalid UTF-8"));

}