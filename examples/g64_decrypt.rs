
use xplugins_crypto;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();    
    let filename = &args[1];
    
    let password = "good-luck-cracking-rsa-sigs-you-pathetic-idiots";
    
    let plain_text = xplugins_crypto::decrypt_file(filename, true, password).expect("Decrypt failed.");

    println!("plain_text:\n{}", plain_text)

}