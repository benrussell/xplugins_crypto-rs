
use xplugins_crypto::rsa;
use std::env;


fn main(){
    let args: Vec<String> = env::args().collect();    
    println!("argc: {}", args.len());

    //let _filename = &args[1];
    
    println!("Verifying file RSA signature...");


/*     
    use std::io::Read;

    let file_open_err = format!("Unable to open source file: {}", filename);
    let mut fh: std::fs::File = std::fs::File::open(filename).expect(&file_open_err);

    let mut data: Vec<u8> = vec!();
    let file_read_err = format!("Unable to read source file: {}", filename);
    fh.read_to_end(&mut data).expect(&file_read_err);
    println!("read {} bytes of encrypted data.", data.len());
 */

    
    //FIXME: PEM file format is not supported.

    //let public_key = include_bytes!("../examples/rsa_keys/x-plugins.com/public.pem");
    //let public_key = include_bytes!("../examples/rsa_keys/x-aviation.com/public.pem");
    let public_key = include_bytes!("../examples/rsa_keys/x-aviation.com/public_key.der");

    let mut data_blob = include_bytes!("../examples/data/IPC_data.lua.G64").to_vec();    
    //let mut data_blob = include_bytes!("../examples/data/license_data.bin").to_vec();    
    let rsa_sig = data_blob.split_off( data_blob.len() - 256 );

    println!("Verifying signature for license_data.bin with xa.pem..");
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