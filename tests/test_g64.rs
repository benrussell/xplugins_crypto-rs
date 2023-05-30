

use xplugins_crypto::g64;



#[test]
fn test_ipc_data_decrypt(){

    // signed internally before encryption
    let gfile = g64::G64File::from_file( "./data/IPC_data.lua.G64", true ).unwrap();

    let dump = gfile.get_hmac().iter().map( |x| format!("{:02x} ",x) ).collect::<String>();
    println!("hmac hex:{}", dump );
    println!("hmac dbg:{:?}", gfile.get_hmac());

    let password = "good-luck-cracking-rsa-sigs-you-pathetic-idiots";
    let data = gfile.decrypt(password);

    assert!( data.is_ok() );

}



#[test]
fn test_ipc_data2_decrypt(){

    // signed internally before encryption
    let gfile = g64::G64File::from_file( "./data/new_ipc_data.bin", true ).unwrap();

    let dump = gfile.get_hmac().iter().map( |x| format!("{:02x} ",x) ).collect::<String>();
    println!("hmac hex:{}", dump );
    println!("hmac dbg:{:?}", gfile.get_hmac());

    let password = "good-luck-cracking-rsa-sigs-you-pathetic-idiots";
    let data = gfile.decrypt(password);

    assert!( data.is_ok() );

}







fn license_file_crypto_password() -> String{
    //FIXME: VMProtect / Obfu
    const PREFIX_SALT: &str = "prefix_salt_8934yu2hjk3brn_1234";
    const SECRET_BLOB: &str = "Hacker, wir wissen wo Dein Auto steht...:410f98e7-d643-4185-a1f3-ca46cfcd2185";

    let hash_input = format!("{}{}",
            PREFIX_SALT,
            SECRET_BLOB
    );

    let digest = md5::compute(hash_input);

    return format!("{:x}", digest);
}


#[test]
fn test_license_data_decrypt(){

    // signed internally before encryption
    let gfile = g64::G64File::from_file( "./data/XA_License_Data_mac.bin", false ).unwrap();

    let dump = gfile.get_hmac().iter().map( |x| format!("{:02x} ",x) ).collect::<String>();
    println!("hmac hex:{}", dump );
    println!("hmac dbg:{:?}", gfile.get_hmac());

    let password = &license_file_crypto_password();
    let data = gfile.decrypt(password);

    assert!( data.is_ok() );

}



fn auth_file_crypto_password() -> String{

    let hash_input = "abcdefg";

    let digest = md5::compute(hash_input);

    return format!("{:x}", digest);
}




#[test]
fn test_activation_login_data_decrypt(){

    // signed internally before encryption
    let gfile = g64::G64File::from_file( "./data/Activation_Login_mac.bin", false ).unwrap();

    let dump = gfile.get_hmac().iter().map( |x| format!("{:02x} ",x) ).collect::<String>();
    println!("hmac hex:{}", dump );
    println!("hmac dbg:{:?}", gfile.get_hmac());

    let password = &auth_file_crypto_password();
    let data = gfile.decrypt(password);

    assert!( data.is_ok() );

}



#[test]
fn test_encrypt_plaintext_blob(){

    let password = "secret";
    let data = "hello world".as_bytes().to_vec();

    let gfile = g64::G64File::from_plaintext_blob( password, data );

    assert!( gfile.is_valid_file().is_ok());

    let recycle = gfile.decrypt(password).unwrap();
    // println!( "recycle:{}", String::from_utf8(recycle).unwrap() );
    println!( "recycle:{:?}", recycle );
    println!( "payload:{:?}", gfile.get_payload() );

}