
// Use the ring::signature to verify a sha1 signature against a public key
use ring::signature::{self, UnparsedPublicKey};

#[derive(Debug)]
struct SignatureError(String);

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "RSA Signature Error: {}", self.0)
    }
}

impl std::error::Error for SignatureError {}


pub fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let public_key =
        //UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, public_key);
        UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, public_key);

    let verified = public_key
        .verify(message, signature)
        .map_err(|_| "Invalid Signature".to_string());

    match verified {
        Ok(_) => Ok("Signature verified.".to_string()),
        Err(_e) => Err(Box::new(SignatureError("Invalid Signature.".to_string()))),
    }
}


pub fn verify_blob_signature(
    public_key: &[u8],
    mut data_blob: Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {

    let rsa_sig = data_blob.split_off( data_blob.len() - 256 );

    verify_signature(&public_key, &rsa_sig, &data_blob)
    
}

