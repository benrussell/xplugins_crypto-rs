
use libaes::Cipher;
use sha2;
use sha2::Digest;
use hmac::{Hmac, Mac};
use hex_literal::hex;


// File structure should be:
// G64000
// Init Vector 128bit (16 bytes)
// HMAC (32 bytes)
// Bytes Payload AES 128 CBC
// 256 byte RSa signature optional


fn get_key_hash( raw_key: &str ) -> [u8; 16]{
    let hash = sha2::Sha256::digest( raw_key );
    let hash_16 = &hash[0..16];
    
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


fn print_hex_blob( data: &Vec<u8> ){
    
    let mut counter_newline = 0;
    let mut counter_space = 0;
    
    for b in data.iter(){
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


pub fn decrypt_file( filename: &str, signed_file: bool, password: &str ) -> Result<String, String>{

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
    //println!("  iv: {:?}", iv);

    let hmac_bytes = get_hmac(&data);
    
    if signed_file {
        //println!("Capturing RSA signature.");
        let _rsa_sig = data_blob.split_off( data_blob.len() - 256 );

        //Verify signature..
        
        //println!("rsa_sig: {:?}", rsa_sig);
    }


    let key = get_key_hash(password);
    
    let mut data_plus_iv = data_blob.clone();
    data_plus_iv.append( &mut iv.to_vec() );

    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut hmac = HmacSha256::new_from_slice(&key)
    .expect("HMAC can take key of any size");
    hmac.update( &data_plus_iv );

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let hmac_result = hmac.finalize();
    // To get underlying array use `into_bytes`, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeats
    // the security provided by the `CtOutput`
    let code_bytes = hmac_result.into_bytes();

    if code_bytes.to_vec() == hmac_bytes.to_vec() {
        println!("HMAC is good.");
    }else{
        println!("hmac: {:?}", hmac_bytes);
        println!("comp: {:?}", code_bytes);
        return Err("HMAC is bad.".to_string());
    }

    let cipher = Cipher::new_128(&key);
    let decrypted = cipher.cbc_decrypt(iv, &data_blob[..]);
    let dec_str = String::from_utf8(decrypted).expect("Unable to convert decrypted data to string.");
    //println!("[{}]", dec_str);
    
    Ok( dec_str )
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
