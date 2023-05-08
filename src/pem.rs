
use base64::{Engine as _, engine::{general_purpose}};

pub fn pem_to_der( filename: &str ) -> Result<Vec<u8>, String>{

    // git will auto-translate line endings inside PEM files
    // so we need code to deal with both forms.

    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    drop(fh);
    println!("read {} bytes of pem data.", data.len());

    let mut data = String::from_utf8(data).expect("UTF-8 error");
    data = data.replace("\r","");
    data = data.replace("\n","");

    const PEM_HEADER: &str = "-----BEGIN PUBLIC KEY-----";
    data = data.replace( PEM_HEADER, "" );
    
    const PEM_FOOTER: &str = "-----END PUBLIC KEY-----";
    data = data.replace( PEM_FOOTER, "" );
    
    let bytes = match general_purpose::STANDARD
            .decode(&data){
                Ok(bytes) => bytes,
                Err(msg) => {
                    // Disable data dump on error..
                    //println!("{:?}", data);
                    //println!("");
                    //println!("Base64 Decode Error: {}", msg);
                    
                    panic!("{}",msg);
                }
        }
        .split_off( 24 );

    Ok(bytes)

}