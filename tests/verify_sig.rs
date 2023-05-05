
use xplugins_crypto::rsa;


fn read_file( filename: &str ) -> Vec<u8>{
    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    drop(fh);
    
    data
}






#[test]
fn verify_rsa_sig_check(){
    
    let public_key_pem_fn = "./data/rsa_keys/x-aviation.com/public.pem";// &args[1];
    //let public_key_pem_fn = "./data/rsa_keys/x-plugins.com/public.pem";// &args[1];
    let public_key = xplugins_crypto::pem::pem_to_der( public_key_pem_fn ).unwrap();
    
    let data_fn = "./data/license_data.bin"; //&args[2];
    let data_blob = read_file( data_fn );
    
    let sig_check = rsa::verify_blob_signature(&public_key, data_blob);

    match sig_check{
        Ok( _ ) => {
            println!("Signature is good.");
            //panic!("good")
        },
        Err( e ) => {
            panic!("{}", e);
            //return Err("Signature is bad.".to_string());
        }
    }

}