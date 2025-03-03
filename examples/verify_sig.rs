
use xplugins_crypto::rsa;
use std::env;



fn print_help(){
    println!("");
    println!("verify_sig: Verify RSA signature of a file.");
    println!("Usage: verify_sig <public.pem> <filename>");
    println!("");
}



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



fn main(){
    let args: Vec<String> = env::args().collect();    
    //println!("argc: {}", args.len());

    if args.len() != 3 {
        print_help();
        return;
    }

    
    let public_key_pem_fn = &args[1];
    let public_key = rsa::public_key::PublicKey::from_pem_file( public_key_pem_fn ).unwrap();

    let data_fn = &args[2];
    let data_blob = read_file( data_fn );
    
    let sig_check = rsa::verify_blob_signature(public_key, data_blob);

    match sig_check{
        Ok( _ ) => {
            println!("Signature is good.");
        },
        Err( e ) => {
            println!("{}", e);
            //return Err("Signature is bad.".to_string());
        }
    }

}