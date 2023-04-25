
use base64::{Engine as _, engine::{general_purpose}};


fn strip_pem_header( mut data: Vec<u8> ) -> Vec<u8>{
    const PEM_HEADER: &str = "-----BEGIN PUBLIC KEY-----\n";
    data = data.split_off( PEM_HEADER.len() );

    data
}


fn strip_pem_footer( mut data: Vec<u8> ) -> Vec<u8>{
    const PEM_HEADER: &str = "-----END PUBLIC KEY-----\n";
    data.truncate(data.len() - PEM_HEADER.len());

    data
}


pub fn pem_to_der( filename: &str ) -> Result<Vec<u8>, String>{

    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    drop(fh);
    //println!("read {} bytes of pem data.", data.len());

    data = strip_pem_header(data);
    data = strip_pem_footer(data);

    let data = String::from_utf8(data).expect("UTF-8 error")
        .replace("\n","");

    let bytes = general_purpose::STANDARD
        .decode(data).unwrap()
        .split_off( 24 );

    Ok(bytes)

}