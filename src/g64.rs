
use libaes::Cipher;
use sha2;
use sha2::Digest;
use hmac::{Hmac, Mac};

// File structure should be:
// G64000
// Init Vector 128bit (16 bytes)
// HMAC (32 bytes)
// Bytes Payload AES 128 CBC
// 256 byte RSA signature optional


pub struct G64File{
    data: Vec<u8>,
    filename: String,
    signed_file: bool,
}

impl G64File{

    pub fn from_file( filename: &str, signed_file: bool ) -> Result<Self,String>{
        use std::io::Read;
    
        let file_open_err = format!("Unable to open source file: {}", filename);
        let mut fh = match std::fs::File::open(filename){
            Ok(fh) => fh,
            Err(_) => return Err(file_open_err),
        };
    
        let mut data: Vec<u8> = vec!();
        let file_read_err = format!("Unable to read source file: {}", filename);
        match fh.read_to_end(&mut data){
            Ok(_) => {},
            Err(_) => return Err(file_read_err),
        }
        
        Ok(
            G64File{
                data,
                filename: filename.to_string(),
                signed_file,
            }
        )  
    }
    

    fn header_len_g64(&self) -> usize{
        6
    }

    fn header_len_iv(&self) -> usize{
        16
    }

    fn header_len_hmac(&self) -> usize{
        32
    }
    
    fn header_len_total(&self) -> usize{
        self.header_len_g64() + self.header_len_iv() + self.header_len_hmac()
    }


    pub fn get_header_g64(&self) -> &[u8]{
        &self.data[0..6]
    }

    pub fn get_iv(&self) -> &[u8]{
        &self.data[6..22]
    }

    pub fn get_hmac(&self) -> &[u8]{
        &self.data[22..54]
    }

    pub fn get_payload(&self) -> &[u8]{
        &self.data[54..]
    }


    fn get_password_hash(&self, raw_key: &str ) -> [u8; 16]{
        let hash = sha2::Sha256::digest( raw_key );
        let hash_16 = &hash[0..16];
        
        let mut ret: [u8; 16] = [0; 16];
        for i in 0..16{
            ret[i] = hash_16[i];
        }
    
        ret
    }
    

    pub fn verify_hmac(&self, password_hash: [u8;16] ) -> Result<String, String>{

        let mut data_plus_iv = self.get_payload().clone().to_vec();
        data_plus_iv.append( &mut self.get_iv().to_vec() );
    
        // Create alias for HMAC-SHA256
        type HmacSha256 = Hmac<sha2::Sha256>;
    
        let mut hmac = HmacSha256::new_from_slice(&password_hash)
                        .expect("HMAC can take key of any size");
        hmac.update( &data_plus_iv );
    
        // `result` has type `CtOutput` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let hmac_result = hmac.finalize();
        // To get underlying array use `into_bytes`, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeats
        // the security provided by the `CtOutput`
        let code_bytes = hmac_result.into_bytes();
    
        if code_bytes.to_vec() == self.get_hmac().to_vec() {
            return Ok("HMAC passed.".to_string());
        }else{
            //println!("hmac: {:?}", hmac_bytes);
            //println!("comp: {:?}", code_bytes);
            return Err("HMAC failed.".to_string());
        }
    
    }


    fn is_valid_file(&self) -> Result<(),String>{

        if self.data.len() < self.header_len_total() {
            return Err(format!("File is too small to be a G64 file: {}", self.filename));
        }
    
        let header = self.get_header_g64();    
        if header == "G64000".as_bytes().to_vec() {
            return Err(format!("Bad header, not a G64 file: {}", self.filename));
        }
    
        if self.data.len() < self.header_len_total() {
            return Err(format!("File too short to be a valid G64 file: {}", self.filename));
        }
        
        Ok(())
    }


    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, String> {

        self.is_valid_file()?;

        let mut header_data = self.data.clone();
        let mut data = header_data.split_off( self.header_len_total() );
        drop(header_data);
        
        if self.signed_file {
            //strip the rsa sig
            let _rsa_sig = data.split_off( data.len() - 256 );
            drop(_rsa_sig);
        }
    
        let password_hash = self.get_password_hash(password);
        drop(password); //lose the plaintext version from the stack

        self.verify_hmac(password_hash)?;
    
        let cipher = Cipher::new_128(&password_hash);
        let decrypted: Vec<u8> = cipher.cbc_decrypt(self.get_iv(), &data).into();
        
        Ok( decrypted )

    }



    pub fn verify_rsa_signature(&self, public_key: crate::rsa::public_key::PublicKey) -> Result<(),String>{
        let data = self.data.clone();
        match crate::rsa::verify_blob_signature( public_key, data ){
            Ok(_) => Ok(()),
            Err(_) => Err("Bad Signature".to_string()),
        }
    }

}




