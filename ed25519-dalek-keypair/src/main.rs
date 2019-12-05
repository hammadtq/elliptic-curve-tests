extern crate rand_core;
extern crate rand_os;
extern crate ed25519_dalek;

//use rand_core::RngCore;
use rand_os::OsRng;
use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
//use ed25519_dalek::Signature;


fn main() {
    let mut csprng: OsRng = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut csprng);

    // let message: &[u8] = b"This is a test of the tsunami alert system.";
    // let signature: Signature = keypair.sign(message);
    let public_key = keypair.public;
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.to_bytes();

    let pk_encoded = hex::encode(public_key_bytes);
    println!("Public Key Hex encoded: {}", pk_encoded);


    let secret_key = &keypair.secret;

    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = secret_key.to_bytes();

    let sk_encoded = hex::encode(secret_key_bytes);
    println!("Secret Key Hex encoded: {}", sk_encoded);

}