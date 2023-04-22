
// File structure should be:
// G64000
// Init Vector 128bit (16 bytes)
// HMAC (32 bytes)
// Bytes Payload AES 128 CBC
// 256 byte RSa signature optional


fn check_header( data: Vec<u8> ) -> Result<String, String>{
    let header = String::from_utf8(data[0..6].to_vec()).expect("Unable to convert header to string.");
    if header != "G64000" {
        return Err(format!("Invalid header: {}", header));
    }
    Ok(header)
}


fn get_iv( data: Vec<u8> ) -> Result<Vec<u8>, String>{
    let iv = data[6..22].to_vec();
    Ok(iv)
}


fn get_hmac( data: Vec<u8> ) -> Result<Vec<u8>, String>{
    let hmac = data[22..54].to_vec();
    Ok(hmac)
}


pub fn decrypt_file( filename: &str ) -> Result<String, String>{

    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    println!("read {} bytes of encrypted data.", data.len());

    println!("check header: {:?}", check_header(data.clone()) );

    let iv = get_iv(data.clone()).expect("Unable to get IV.");
    println!("  iv: {:?}", iv);

    let hmac = get_hmac(data.clone()).expect("Unable to get HMAC.");
    println!("hmac: {:?}", hmac);

    let payload_offset = 6 + 16 + 32;
    let data = data.split_off(payload_offset);

    for b in data.iter(){
        print!("{:x} ", b);
    }
    //println!("data: {:x}", data);

    Ok("fubar".to_string())
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
