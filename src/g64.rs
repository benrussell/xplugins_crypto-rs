

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

    //FIXME: rename to: from_encrypted_file
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
    
    
    //FIXME: need from_encrypted_blob(...) constructor


    pub fn from_plaintext_blob( password: &str, data: Vec<u8> ) -> G64File{

        let header_g64 = "G64000".as_bytes();

        let mut header_iv: [u8; 16] = [0;16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut header_iv); //FIXME: use a stronger RNG

        let password_hash = G64File::get_password_hash( password );
        
        let cipher = Cipher::new_128(&password_hash);
        let data_encrypted: Vec<u8> = cipher.cbc_encrypt(&header_iv, &data).into();
        
        let header_hmac = G64File::generate_hmac(password_hash, &data_encrypted, header_iv);

        let mut blob: Vec<u8> = vec!();
        blob.extend_from_slice( header_g64 );
        blob.extend_from_slice( &header_iv );
        blob.extend_from_slice( &header_hmac );
        blob.extend_from_slice( &data_encrypted );
        let blob = blob; //strip mutability


        let ret = G64File{
            data: blob,
            filename: "plaintext_blob".to_string(),
            signed_file: false,
        };

        ret.is_valid_file().unwrap();
        ret.verify_hmac(password_hash).unwrap();

        ret


    }



    pub fn save_to_file(&self, filename: &str) -> Result<(),String>{
        
        let mut file = match std::fs::File::create(&filename) {
            Err(why) => panic!("couldn't create {}: {}", filename, why),
            Ok(file) => file,
        };

        match std::io::Write::write_all(&mut file, self.data.as_slice()){
            Ok(_) => Ok(()),
            Err(_) => return Err("write failed".to_string()),
        }

    }



    
    fn header_len_total(&self) -> usize{
        const HEADER_LEN_G64 : usize = 6;
        const HEADER_LEN_IV : usize = 16;
        const HEADER_LEN_HMAC : usize = 32;

        // self.header_len_g64() + self.header_len_iv() + self.header_len_hmac()
        HEADER_LEN_G64 + HEADER_LEN_IV + HEADER_LEN_HMAC
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
        if self.signed_file {
            //strip the signature!
            &self.data[ 54.. self.data.len()-256 ]

        }else{
            &self.data[54..]    
        }
    }


    // static fn
    fn get_password_hash(raw_key: &str ) -> [u8; 16]{
        let hash = sha2::Sha256::digest( raw_key );
        let hash_16 = &hash[0..16];
        
        let mut ret: [u8; 16] = [0; 16];
        for i in 0..16{
            ret[i] = hash_16[i];
        }
    
        ret
    }
    

    // static fn
    fn generate_hmac( password_hash: [u8;16], data: &Vec<u8>, iv: [u8; 16]) -> [u8; 32]{

        // hmac wants <data><iv> .... not <iv><data>
        let mut data = data.clone();
        let mut iv = iv.clone().to_vec();
        data.append( &mut iv );
        let data_plus_iv = data.as_slice();

        // Create alias for HMAC-SHA256
        type HmacSha256 = Hmac<sha2::Sha256>;
    
        let mut hmac = HmacSha256::new_from_slice(&password_hash)
                        .expect("HMAC can take key of any size"); //FIXME: Weird error message
        hmac.update( &data_plus_iv );
    
        // `result` has type `CtOutput` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let hmac_result = hmac.finalize();
        // To get underlying array use `into_bytes`, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeats
        // the security provided by the `CtOutput`
        let hmac_bytes: [u8; 32] = hmac_result.into_bytes().into();
        
        hmac_bytes
    
    }



    pub fn verify_hmac(&self, password_hash: [u8;16] ) -> Result<(), String>{

        //FIXME: use generate_hmac to avoid code duplication

        let mut data_plus_iv = self.get_payload().clone().to_vec();
        data_plus_iv.append( &mut self.get_iv().to_vec() );
    
        // Create alias for HMAC-SHA256
        type HmacSha256 = Hmac<sha2::Sha256>;
    
        let mut hmac = HmacSha256::new_from_slice(&password_hash)
                        .expect("HMAC can take key of any size"); //FIXME: Weird error message
        hmac.update( &data_plus_iv );
    
        // `result` has type `CtOutput` which is a thin wrapper around array of
        // bytes for providing constant time equality check
        let hmac_result = hmac.finalize();
        // To get underlying array use `into_bytes`, but be careful, since
        // incorrect use of the code value may permit timing attacks which defeats
        // the security provided by the `CtOutput`
        let hmac_bytes = hmac_result.into_bytes();
        let blob_bytes = self.get_hmac();
    
        if hmac_bytes.to_vec() == blob_bytes.to_vec() {
            return Ok(());
        }else{
            //println!("hmac: {:?}", hmac_bytes);
            //println!("blob: {:?}", blob_bytes);
            return Err("HMAC failed.".to_string());
        }
    
    }


    pub fn is_valid_file(&self) -> Result<(),String>{

        if self.data.len() < self.header_len_total() {
            return Err(format!("File is too small to be a G64 file: {}", self.filename));
        }
    
        let header = self.get_header_g64();    
        if header != "G64000".as_bytes().to_vec() {
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
    
        //println!("password hash input: [{}]", password);
        let password_hash = G64File::get_password_hash(password);
        //drop(password); //lose the plaintext version from the stack
        //println!("password_hash: {:?}", password_hash);
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




