

use base64::{Engine as _, engine::{general_purpose}};

pub struct PublicKey{
    key_bytes_der_format: Vec<u8>,
}


impl PublicKey{

    pub fn from_bytes( bytes: Vec<u8> ) -> Option<Self>{
        let new_key = PublicKey { 
            key_bytes_der_format: bytes
        };

        Some(new_key)
    }
    
    pub fn from_pem_bytes( pem_bytes: Vec<u8> ) -> Option<Self>{        
        let der_bytes = PublicKey::pem_to_der( pem_bytes );
        PublicKey::from_bytes( der_bytes )
    }

    // Loads a DER-format key
    pub fn from_file( filename: &str ) -> Option<Self>{
        //FIXME: Check file extension...
        let der_bytes = match PublicKey::file_loader(filename){
            Ok(bytes) => bytes,
            Err(_msg) => return None,
        };        
        PublicKey::from_bytes( der_bytes )
    }

    // Loads a PEM-format key. Data is tranlsated interanlly to DER format.
    pub fn from_pem_file( filename: &str ) -> Option<Self>{        
        //FIXME: Check file extension...        
        let pem_bytes = match PublicKey::file_loader(filename){
            Ok(bytes) => bytes,
            Err(_msg) => return None,
        };
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


    fn file_loader( filename: &str ) -> Result<Vec<u8>,String> {
        use std::io::Read;

        let file_open_err = format!("Unable to open source file: {}", filename);
        let mut fh: std::fs::File = match std::fs::File::open(filename){
            Ok(fh) => fh,
            Err(_) => return Err(format!("{}", file_open_err)),
        };
    
        let mut data: Vec<u8> = vec!();
        let file_read_err = format!("Unable to read source file: {}", filename);
        match fh.read_to_end(&mut data){
            Ok(_) => {},
            Err(_) => return Err(format!("{}", file_read_err)),
        }
        drop(fh);
        // println!("read {} bytes of pem data.", data.len());

        Ok(data)
    }


    pub fn data(&self) -> &Vec<u8>{
        &self.key_bytes_der_format
    }

}