
use xplugins_crypto::rsa;
use std::env;


fn main(){
    let args: Vec<String> = env::args().collect();    
    println!("argc: {}", args.len());

    //let _filename = &args[1];
    
    println!("Verifying file RSA signature...");
    
    let public_key = include_bytes!("../examples/rsa_keys/x-plugins.com/public.pem");
    //let public_key = include_bytes!("../examples/rsa_keys/x-aviation.com/public.pem");

    let mut data_blob = include_bytes!("../examples/data/IPC_data.lua.G64").to_vec();    
    let rsa_sig = data_blob.split_off( data_blob.len() - 256 );

    println!("Verifying signature..");
    let sig_check = rsa::verify_signature(public_key, &rsa_sig, &data_blob);

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