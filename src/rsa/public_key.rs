#[allow(dead_code)]


use base64::{Engine as _, engine::{general_purpose}};

struct PublicKey{
    key_bytes_der_format: Vec<u8>,
}


impl PublicKey{

    pub fn from_bytes( bytes: Vec<u8> ) -> Self{
        PublicKey { 
            key_bytes_der_format: bytes
        }        
    }
    
    pub fn from_pem_bytes( pem_bytes: Vec<u8> ) -> Self{        
        let der_bytes = PublicKey::pem_to_der( pem_bytes );
        PublicKey::from_bytes( der_bytes )
    }

    // Loads a DER-format key
    pub fn from_file( filename: &str ) -> Self{
        let der_bytes = PublicKey::file_loader(filename);
        PublicKey::from_bytes( der_bytes )
    }

    // Loads a PEM-format key. Data is tranlsated interanlly to DER format.
    pub fn from_pem_file( filename: &str ) -> Self{        
        let pem_bytes = PublicKey::file_loader(filename);        
        PublicKey::from_pem_bytes(pem_bytes)
    }



    // Converts a PEM blob into DER bytes
    fn pem_to_der( pem_bytes: Vec<u8> ) -> Vec<u8>{
        
        let mut data = String::from_utf8(pem_bytes).expect("UTF-8 error");
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

        bytes

    }


    fn file_loader( filename: &str ) -> Vec<u8> {
        use std::io::Read;

        let file_open_err = format!("Unable to open source file: {}", filename);
        let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);
    
        let mut data: Vec<u8> = vec!();
        let file_read_err = format!("Unable to read source file: {}", filename);
        fh.read_to_end(&mut data).expect(&file_read_err);
        drop(fh);
        println!("read {} bytes of pem data.", data.len());

        data
    }


    pub fn data(&self) -> &Vec<u8>{
        &self.key_bytes_der_format
    }

}