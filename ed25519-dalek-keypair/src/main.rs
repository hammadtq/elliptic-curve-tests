extern crate rand_core;
extern crate rand_os;
extern crate ed25519_dalek;
extern crate curve25519_dalek;
use curve25519_dalek::digest::generic_array::typenum::U64;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::ristretto;

extern crate hex;

use sha2::Sha512;
use core::fmt::Debug;
use hex::FromHex;
//use rand_core::RngCore;
use rand_os::OsRng;
use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, PublicKey, SecretKey};
//use ed25519_dalek::Signature;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants;


#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct QuisQuisPublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for QuisQuisPublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "QuisQuisPublicKey({:?}), {:?})", self.0, self.1)
    }
}

#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct randomizedGeneratorPoint(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for randomizedGeneratorPoint {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "RandomizedGenerator({:?}), {:?})", self.0, self.1)
    }
}

fn main() {
    let mut csprng: OsRng = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let random: Scalar = Scalar::random(&mut csprng);
    println!("random cspring: {:?}", random);
    println!("Generated secret key: {:?}", keypair.secret);


    let public_key = keypair.public;
    println!("Generated public key: {:?}", public_key);
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.to_bytes();
    println!("Generated public key in bytes: {:?}", public_key_bytes);

    let secret_key = keypair.secret;

    // Creating our own public key
    let mut csprng: OsRng = OsRng::new().unwrap();
    let a: Scalar = Scalar::random(&mut csprng);

    let quisquis_public_key = generate_quisquis_pk(public_key, a);

    println!("complete key g^r^sk: {:?}", quisquis_public_key);

    let randomized_g = randomize_the_generator(a);

    println!("randomized generator: {:?}", randomized_g);

    // now verify if g^r * sk is equal to g^r^sk
    let verified = verify_kp(quisquis_public_key, randomized_g, secret_key); 
    println!("verified: {:?}", verified);
    // let pk_encoded = hex::encode(public_key_bytes);
    // println!("Public Key Hex encoded: {}", pk_encoded);


    // //Lets suppose we got the public key from someone, so here we will decode and return to the original public key
    // let pk_decoded = <[u8; 32]>::from_hex(pk_encoded).expect("PK string to bytes decoding failed");
    // println!("Public Key Hex decoded: {:?}", pk_decoded);

    // let public_key_decoded: PublicKey = PublicKey::from_bytes(&public_key_bytes).expect("Decoding to PK failed");
    // println!("Public Key decoded: {:?}", &public_key_decoded);

    // print_type_of(&public_key_decoded);

    // let edwards_point = public_key_decoded.get_edwards_point();
    
    // println!("Edwards Point: {:?}", &edwards_point);


    // let secret_key = &keypair.secret;

    // let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = secret_key.to_bytes();

    // let sk_encoded = hex::encode(secret_key_bytes);
    // println!("Secret Key Hex encoded: {}", sk_encoded);

}
fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}


/// generate_quisquis_pk()
/// @params public_key, randomizedGeneratorPoint, SecretKey
/// 
/// Verify if we correctly created a (pk,sk) pair after randomizing it with a scalar r
/// 
/// Function: g^r * sk = g^r^sk
/// Output: bool


fn generate_quisquis_pk(public_key: PublicKey, a: Scalar) -> QuisQuisPublicKey{

    let public_key_edwards = public_key.get_edwards_point();

    // let mut h: Sha512 = Sha512::new();
    // let mut hash: [u8; 64] = [0u8; 64];
    // let mut digest: [u8; 32] = [0u8; 32];

    // h.input(a);
    // hash.copy_from_slice(h.result().as_slice());

    // digest.copy_from_slice(&hash[..32]);
    // let bits = &mut digest;
    //let bits = &a.to_bytes();
    let new_point = &Scalar::from_bits(a.to_bytes()) * public_key_edwards;
    let compressed = new_point.compress();

    //println!("a random scalar: {:?}", a);
    //println!("new public key g^r^sk: {:?}", compressed);

    QuisQuisPublicKey(compressed, new_point)
    
}

fn randomize_the_generator(a: Scalar) -> randomizedGeneratorPoint{

    let new_point = &Scalar::from_bits(a.to_bytes()) * &constants::ED25519_BASEPOINT_TABLE;
    let compressed = new_point.compress();

    //println!("a random scalar: {:?}", a);
    //println!("new public key g^r^sk: {:?}", compressed);

    randomizedGeneratorPoint(compressed, new_point)
    
}

/// verify_kp()
/// @params quisquis_public_key, randomizedGeneratorPoint, SecretKey
/// 
/// Verify if we correctly created a (pk,sk) pair after randomizing it with a scalar r
/// 
/// Function: g^r * sk = g^r^sk
/// Output: bool


fn verify_kp(quisquis_public_key: QuisQuisPublicKey, randomPoint: randomizedGeneratorPoint, sk: SecretKey) -> bool{

    let mut h: Sha512 = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.input(sk.as_bytes());
    hash.copy_from_slice(h.result().as_slice());

    digest.copy_from_slice(&hash[..32]);
    let bits = &mut digest;

    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;

    let mul_sk_r =  &Scalar::from_bits(*bits) * &randomPoint.1;
    let new_mul = mul_sk_r.compress();
    println!("secret key: {:?}", sk);
    
    println!("random point: {:?}", randomPoint.0);

    println!("multiplied g^r^sk: {:?}", new_mul);

    println!("QuisQuis PublicKey {:?}", quisquis_public_key.0);

    if new_mul == quisquis_public_key.0 {
        return true
    }else{
        return false
    }
}