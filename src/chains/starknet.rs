use starknet_core::crypto::{ecdsa_sign, ecdsa_verify, Signature, ExtendedSignature};
use starknet_crypto::{FieldElement as CryptoFieldElement, recover};
use starknet_types_core::felt::Felt;
use thiserror::Error;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use stark_curve::{
    AffinePoint, FieldElement as CurveFieldElement, ProjectivePoint, Scalar, StarkCurve,
};
use stark_curve::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use stark_curve::ff::PrimeField;
use stark_curve::elliptic_curve::subtle::{Choice, CtOption};
use generic_array::GenericArray;
use stark_curve::U256;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("ECDSA sign failed")]
    SignError,
    #[error("Public key recovery failed")]
    RecoverError,
    #[error("Invalid point on curve")]
    PointError,
    #[error("Symmetric encryption/decryption failed")]
    SymmetricError,
    #[error("Scalar conversion failed")]
    ScalarError,
    #[error("Field element conversion failed")]
    FieldError,
    #[error("Decode error")]
    DecodeError,
}

/// Struct to hold encrypted data
#[derive(Debug)]
pub struct WrappedKey {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
}

/// Helper function to compute y-coordinate from x and parity bit
fn compute_y_from_x(x: CurveFieldElement, y_is_odd: bool) -> Result<CurveFieldElement, CryptoError> {
    // Stark curve equation: y^2 = x^3 + ax + b
    // For StarkCurve, a = 1, b = 0x314159265d... (as per curve params)
    let a = CurveFieldElement::ONE;
    let b = CurveFieldElement::from_hex("0x314159265dd8bf6a8870de7bf5c2c519").map_err(|_| CryptoError::FieldError)?;
    let x_square = x.square();
    let x_cube = x_square * x;
    let y_square = x_cube + a * x + b;
    
    // Compute square root (mod p)
    let y = y_square.sqrt().into_option().ok_or(CryptoError::PointError)?;
    
    // Choose the correct y based on parity
    let y_bytes = y.to_repr();
    let y_is_odd_actual = (y_bytes[31] & 1) == 1;
    if y_is_odd_actual == y_is_odd {
        Ok(y)
    } else {
        Ok(-y)
    }
}

/// Sign a message hash, returning the ExtendedSignature
pub fn sign_with_recovery(
    privkey: &Felt,
    msg_hash: &Felt,
) -> Result<ExtendedSignature, CryptoError> {
    ecdsa_sign(privkey, msg_hash).map_err(|_| CryptoError::SignError)
}

/// Recover public key from a signature and message hash
pub fn recover_pubkey(
    msg_hash: &Felt,
    sig: &ExtendedSignature,
) -> Result<Felt, CryptoError> {
    let msg_fe = CryptoFieldElement::from_bytes_be(&msg_hash.to_bytes_be())
        .map_err(|_| CryptoError::RecoverError)?;
    let r_fe = CryptoFieldElement::from_bytes_be(&sig.r.to_bytes_be())
        .map_err(|_| CryptoError::RecoverError)?;
    let s_fe = CryptoFieldElement::from_bytes_be(&sig.s.to_bytes_be())
        .map_err(|_| CryptoError::RecoverError)?;
    let v_fe = CryptoFieldElement::from_bytes_be(&sig.v.to_bytes_be())
        .map_err(|_| CryptoError::RecoverError)?;

    let pubkey_fe = recover(&msg_fe, &r_fe, &s_fe, &v_fe)
        .map_err(|_| CryptoError::RecoverError)?;
    println!("pubkey_fe: {:?}", pubkey_fe);

    Ok(Felt::from_bytes_be(&pubkey_fe.to_bytes_be()))
}

/// Verify a signature given pubkey, msg_hash, and Signature
pub fn verify_signature(
    pubkey: &Felt,
    msg_hash: &Felt,
    sig: &Signature,
) -> bool {
    ecdsa_verify(pubkey, msg_hash, sig).unwrap_or(false)
}

/// Encrypt a decryption key with a public key recovered from signature
pub fn encrypt_key(
    signature: &ExtendedSignature,
    message_hash: &Felt,
    decryption_key: &str,
) -> Result<WrappedKey, CryptoError> {
    let pubkey = recover_pubkey(message_hash, signature)?;
    
    // Reconstruct affine point from x and parity
    let y_is_odd = (signature.v.to_bytes_be()[31] & 1) == 1;
    let x = CurveFieldElement::from_repr(GenericArray::clone_from_slice(&pubkey.to_bytes_be()))
        .into_option()
        .ok_or(CryptoError::FieldError)?;
    let y = compute_y_from_x(x, y_is_odd)?;
    let encoded = EncodedPoint::<StarkCurve>::from_affine_coordinates(
        &x.to_repr(),
        &y.to_repr(),
        false,
    );
    let recipient_affine_opt = AffinePoint::from_encoded_point(&encoded);
    if recipient_affine_opt.is_none().into() {
        return Err(CryptoError::PointError);
    }
    let recipient_affine = recipient_affine_opt.unwrap();

    // Generate ephemeral scalar and public key
    let mut rng = OsRng;
    // Generate random scalar manually
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let eph_sk = Scalar::from_be_bytes_mod_order(&random_bytes);
    
    let gen_affine = AffinePoint::GENERATOR;
    let gen_proj: ProjectivePoint = gen_affine.into();
    let eph_proj = gen_proj * eph_sk;
    let eph_affine: AffinePoint = eph_proj.into();

    // Shared secret = recipient_affine * eph_sk
    let shared_proj = ProjectivePoint::from(recipient_affine) * eph_sk;
    let shared_affine: AffinePoint = shared_proj.into();

    // Derive AES key using SHA-256 of shared secret's x-coordinate
    let encoded_shared = shared_affine.to_encoded_point(false);
    let shared_x = encoded_shared.x().ok_or(CryptoError::PointError)?;
    let mut h = Sha256::new();
    h.update(shared_x);
    let aes_key_bytes = h.finalize();
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

    // AES-GCM encrypt the decryption_key
    let cipher = Aes256Gcm::new(aes_key);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, decryption_key.as_bytes())
        .map_err(|_| CryptoError::SymmetricError)?;

    // Serialize ephemeral public key (uncompressed: x || y)
    let encoded_eph = eph_affine.to_encoded_point(false);
    let eph_x = encoded_eph.x().ok_or(CryptoError::PointError)?;
    let eph_y = encoded_eph.y().ok_or(CryptoError::PointError)?;
    let mut eph_bytes = Vec::with_capacity(64);
    eph_bytes.extend_from_slice(eph_x);
    eph_bytes.extend_from_slice(eph_y);

    Ok(WrappedKey {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        ephemeral_pubkey: eph_bytes,
    })
}

/// Decrypt the wrapped key using the private key
pub fn decrypt_key(
    privkey: &Felt,
    wrapped: &WrappedKey,
) -> Result<String, CryptoError> {
    if wrapped.ephemeral_pubkey.len() != 64 {
        return Err(CryptoError::PointError);
    }

    // Parse ephemeral pubkey x and y
    let eph_x_repr = GenericArray::clone_from_slice(&wrapped.ephemeral_pubkey[0..32]);
    let eph_y_repr = GenericArray::clone_from_slice(&wrapped.ephemeral_pubkey[32..64]);
    let eph_x = CurveFieldElement::from_repr(eph_x_repr)
        .into_option()
        .ok_or(CryptoError::FieldError)?;
    let eph_y = CurveFieldElement::from_repr(eph_y_repr)
        .into_option()
        .ok_or(CryptoError::FieldError)?;

    let encoded = EncodedPoint::<StarkCurve>::from_affine_coordinates(
        &eph_x.to_repr(),
        &eph_y.to_repr(),
        false,
    );
    let eph_affine_opt = AffinePoint::from_encoded_point(&encoded);
    if eph_affine_opt.is_none().into() {
        return Err(CryptoError::PointError);
    }
    let eph_affine = eph_affine_opt.unwrap();

    // Convert privkey to Scalar
    let priv_repr = GenericArray::clone_from_slice(&privkey.to_bytes_be());
    let priv_scalar = Scalar::from_repr(priv_repr)
        .into_option()
        .ok_or(CryptoError::ScalarError)?;

    // Shared secret = eph_affine * priv_scalar
    let shared_proj = ProjectivePoint::from(eph_affine) * priv_scalar;
    let shared_affine: AffinePoint = shared_proj.into();

    // Derive AES key
    let encoded_shared = shared_affine.to_encoded_point(false);
    let shared_x = encoded_shared.x().ok_or(CryptoError::PointError)?;
    let mut h = Sha256::new();
    h.update(shared_x);
    let aes_key_bytes = h.finalize();
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

    // Decrypt
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&wrapped.nonce);
    let plaintext = cipher.decrypt(nonce, wrapped.ciphertext.as_ref())
        .map_err(|_| CryptoError::SymmetricError)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::DecodeError)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_with_recovery() {
        let privkey = Felt::from_hex("0x0").unwrap();
        let msg_hash = Felt::from_hex("0x1234567890abcdef").unwrap();
        let sig = sign_with_recovery(&privkey, &msg_hash).unwrap();
        println!("r: {:?}, s: {:?}, v: {:?}, sig: {:?}", sig.r, sig.s, sig.v, sig);
        let pubkey = recover_pubkey(&msg_hash, &sig).unwrap();
        println!("pubkey: {:?}", pubkey);
        assert_eq!(pubkey, "0x0".parse::<Felt>().unwrap());
    }
}