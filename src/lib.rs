
use libaes::Cipher;
//use sha256;
use sha2;
use sha2::Digest;

// File structure should be:
// G64000
// Init Vector 128bit (16 bytes)
// HMAC (32 bytes)
// Bytes Payload AES 128 CBC
// 256 byte RSa signature optional


fn get_key_hash( raw_key: &str ) -> [u8; 16]{

    println!("raw key: {}", raw_key);

    let hash = sha2::Sha256::digest( raw_key );
    let hash_16 = &hash[0..16];

    println!("   hash: {:x}", hash);
    println!("hash_16: {:?}", hash_16);
    
    let mut ret: [u8; 16] = [0; 16];
    for i in 0..16{
        ret[i] = hash_16[i];
    }

    ret

}


fn check_header( data: &Vec<u8> ) -> Result<String, String>{
    let header = String::from_utf8(data[0..6].to_vec()).expect("Unable to convert header to string.");
    if header != "G64000" {
        return Err(format!("Invalid header: {}", header));
    }
    Ok(header)
}


fn get_iv( data: &Vec<u8> ) -> &[u8] {
    &data[6..22]
}


fn get_hmac( data: &Vec<u8> ) -> &[u8] {
    &data[22..54]    
}


pub fn decrypt_file( filename: &str, signed_file: bool ) -> Result<String, String>{

    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    println!("read {} bytes of encrypted data.", data.len());

    const HEADER_LEN_G64: usize = 6;
    const HEADER_LEN_IV: usize = 16;
    const HEADER_LEN_HMAC: usize = 32;
    const HEADER_LEN_BLOB: usize = HEADER_LEN_G64 + HEADER_LEN_IV + HEADER_LEN_HMAC;

    if data.len() < HEADER_LEN_BLOB {
        return Err(format!("File too short to be a valid G64 file: {}", filename));
    }

    let mut data_blob = data.split_off( HEADER_LEN_BLOB );
    println!("Checking header: {:?}", check_header(&data) );

    let iv = get_iv(&data);
    println!("  iv: {:?}", iv);

    let hmac = get_hmac(&data);
    println!("hmac: {:?}", hmac);



    if signed_file {
        println!("Capturing RSA signature.");
        let _rsa_sig = data_blob.split_off( data_blob.len() - 256 );

        //println!("rsa_sig: {:?}", rsa_sig);
    }


    const PRINT_BLOB: bool = true;
    if PRINT_BLOB {
        //print a hex dump of the data segment
        println!("AES Payload:");
        let mut counter_newline = 0;
        let mut counter_space = 0;
        for b in data_blob.iter(){
            print!("{:02x}", b);


            counter_space += 1;
            if counter_space == 4 {
                print!(" ");
                counter_space = 0;
            }


            counter_newline += 1;
            if counter_newline >= 36 {
                println!("");
                counter_newline = 0;
                counter_space = 0;
            }
        
            
        }
    }
    
    println!("");


    let readable_password = "good-luck-cracking-rsa-sigs-you-pathetic-idiots";

    let key = get_key_hash(readable_password);
    for b in key.iter(){
        print!("{:02x}", b);
    }
    println!("");

    let cipher = Cipher::new_128(&key);

    let decrypted = cipher.cbc_decrypt(iv, &data_blob[..]);


    let dec_str = String::from_utf8(decrypted).expect("Unable to convert decrypted data to string.");
    println!("[{}]", dec_str);

    //println!("{:?}", decrypted);


    
    Ok("no_decrypt".to_string())
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
