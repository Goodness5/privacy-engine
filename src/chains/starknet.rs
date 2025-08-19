use starknet_core::crypto::{ ecdsa_sign, ecdsa_verify, Signature };
use starknet_crypto::{recover, ExtendedSignature, FieldElement as CryptoFieldElement};
use starknet_types_core::felt::Felt;
use crate::traits::crypto::CryptoProtocol;
use crate::types::{ CryptoError, EncryptedData, WrappedKey };

pub struct StarknetProtocol;
use aes_gcm::{ aead::{ Aead, KeyInit, OsRng, rand_core::RngCore }, Aes256Gcm, Key, Nonce };
use sha2::{ Digest, Sha256 };
use stark_curve::{
    AffinePoint,
    FieldElement as CurveFieldElement,
    ProjectivePoint,
    Scalar,
    StarkCurve,
};
use stark_curve::elliptic_curve::sec1::{ EncodedPoint, FromEncodedPoint };
use stark_curve::ff::PrimeField;
use stark_curve::primeorder::Field;
use stark_curve::elliptic_curve::sec1::ToEncodedPoint;


impl StarknetProtocol {
    /// Helper function to compute y-coordinate from x and parity bit
    fn compute_y_from_x(
        x: CurveFieldElement,
        y_is_odd: bool
    ) -> Result<CurveFieldElement, CryptoError> {
        // Stark curve equation: y^2 = x^3 + ax + b
        // For StarkCurve, a = 1, b = 0x06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89
        let a = CurveFieldElement::ONE;
        let b_bytes = hex
            ::decode("06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89")
            .map_err(|_| CryptoError::FieldError)?;
        let b = CurveFieldElement::from_be_bytes_mod_order(&b_bytes);

        let x_square = x.square();
        let x_cube = x_square * x;
        let y_square = x_cube + a * x + b;

        // Compute square root (mod p)
        let y = y_square.sqrt().into_option().ok_or(CryptoError::PointError)?;

        // Choose the correct y based on parity
        let y_repr = y.to_repr();
        let y_is_odd_actual = (y_repr[31] & 1) == 1;

        Ok(if y_is_odd_actual == y_is_odd { y } else { -y })
    }

    /// Recover public key from a signature and message hash
    pub fn recover_pubkey(msg_hash: &Felt, sig: &ExtendedSignature) -> Result<Felt, CryptoError> {
        let msg_fe = CryptoFieldElement::from_bytes_be(&msg_hash.to_bytes_be()).map_err(
            |_| CryptoError::RecoverError
        )?;
        let r_fe = CryptoFieldElement::from_bytes_be(&sig.r.to_bytes_be()).map_err(
            |_| CryptoError::RecoverError
        )?;
        let s_fe = CryptoFieldElement::from_bytes_be(&sig.s.to_bytes_be()).map_err(
            |_| CryptoError::RecoverError
        )?;
        let v_fe = CryptoFieldElement::from_bytes_be(&sig.v.to_bytes_be()).map_err(
            |_| CryptoError::RecoverError
        )?;

        let pubkey_fe = recover(&msg_fe, &r_fe, &s_fe, &v_fe).map_err(
            |_| CryptoError::RecoverError
        )?;
        println!("pubkey_fe: {:?}", pubkey_fe);

        Ok(Felt::from_bytes_be(&pubkey_fe.to_bytes_be()))
    }
}


impl CryptoProtocol for StarknetProtocol {
    fn verify_signature(
        &self,
        pubkey: &[u8],
        msg_hash: &[u8],
        sig: &[u8]
    ) -> Result<bool, CryptoError> {
        // Convert pubkey bytes to Felt
        let pubkey_bytes: [u8; 32] = pubkey.try_into().map_err(|_| CryptoError::SignError)?;
        let pubkey_felt = Felt::from_bytes_be(&pubkey_bytes);

        // Convert message hash to Felt
        let msg_hash_bytes: [u8; 32] = msg_hash.try_into().map_err(|_| CryptoError::SignError)?;
        let msg_hash_felt = Felt::from_bytes_be(&msg_hash_bytes);

        // Convert signature bytes to Signature struct
        if sig.len() != 64 {
            return Err(CryptoError::SignError);
        }

        let r_bytes: [u8; 32] = sig[..32].try_into().map_err(|_| CryptoError::SignError)?;
        let s_bytes: [u8; 32] = sig[32..].try_into().map_err(|_| CryptoError::SignError)?;

        let r = Felt::from_bytes_be(&r_bytes);
        let s = Felt::from_bytes_be(&s_bytes);
        let signature = Signature { r, s };

        Ok(ecdsa_verify(&pubkey_felt, &msg_hash_felt, &signature).unwrap_or(false))
    }

fn sign_message(&self, privkey: &[u8], msg_hash: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let privkey_bytes: [u8; 32] = privkey.try_into().map_err(|_| CryptoError::SignError)?;
        let privkey_felt = Felt::from_bytes_be(&privkey_bytes);

        let msg_hash_bytes: [u8; 32] = msg_hash.try_into().map_err(|_| CryptoError::SignError)?;
        let msg_hash_felt = Felt::from_bytes_be(&msg_hash_bytes);

        let signature = ecdsa_sign(&privkey_felt, &msg_hash_felt).map_err(
            |_| CryptoError::SignError
        )?;

        // Compute public key from private key
        let priv_scalar = Scalar::from_be_bytes_mod_order(&privkey_bytes);
        let gen_affine = AffinePoint::GENERATOR;
        let pub_point: ProjectivePoint = gen_affine.into();
        let pub_affine: AffinePoint = (pub_point * priv_scalar).into();
        let pub_encoded = pub_affine.to_encoded_point(false);
        let pub_x = pub_encoded.x().ok_or(CryptoError::PointError)?;

        // Convert GenericArray to [u8; 32]
        let pub_x_bytes: [u8; 32] = pub_x.as_slice().try_into().map_err(|_| CryptoError::SignError)?;
        let pubkey_felt = Felt::from_bytes_be(&pub_x_bytes);

        // Compute possible public keys from signature
        let r_fe = CryptoFieldElement::from_bytes_be(&signature.r.to_bytes_be())
            .map_err(|_| CryptoError::SignError)?;
        let s_fe = CryptoFieldElement::from_bytes_be(&signature.s.to_bytes_be())
            .map_err(|_| CryptoError::SignError)?;
        let msg_fe = CryptoFieldElement::from_bytes_be(&msg_hash_felt.to_bytes_be())
            .map_err(|_| CryptoError::SignError)?;

        // Try recovery IDs (0 or 1)
        let mut v_value = None;
        for v in 0..2 {
            // Convert i32 to u32 to satisfy From<u32> for CryptoFieldElement
            let v_fe = CryptoFieldElement::from(v as u32);
            if let Ok(recovered_fe) = recover(&msg_fe, &r_fe, &s_fe, &v_fe) {
                let recovered_felt = Felt::from_bytes_be(&recovered_fe.to_bytes_be());
                if recovered_felt == pubkey_felt {
                    v_value = Some(v_fe);
                    break;
                }
            }
        }

        let v_fe = v_value.ok_or(CryptoError::RecoverError)?;

        // Construct extended signature [r|s|v]
        let mut sig_bytes = Vec::with_capacity(96);
        sig_bytes.extend_from_slice(&signature.r.to_bytes_be());
        sig_bytes.extend_from_slice(&signature.s.to_bytes_be());
        sig_bytes.extend_from_slice(&v_fe.to_bytes_be());

        Ok(sig_bytes)
    }
    
    fn encrypt_key(
        &self,
        sig_or_pubkey: &[u8],
        msg_hash: Option<&[u8]>,
        decryption_key: &str
    ) -> Result<crate::types::WrappedKey, CryptoError> {

        let mut signature = ExtendedSignature {
            r: CryptoFieldElement::ZERO,
            s: CryptoFieldElement::ZERO,
            v: CryptoFieldElement::ZERO,
        };
        let pubkey = if let Some(hash) = msg_hash {
            // We were given a signature and message hash
            if sig_or_pubkey.len() != 96 {
                // r(32) + s(32) + v(32)
                return Err(CryptoError::SignError);
            }

            let r_bytes: [u8; 32] = sig_or_pubkey[..32]
                .try_into()
                .map_err(|_| CryptoError::SignError)?;
            let s_bytes: [u8; 32] = sig_or_pubkey[32..64]
                .try_into()
                .map_err(|_| CryptoError::SignError)?;
            let v_bytes: [u8; 32] = sig_or_pubkey[64..]
                .try_into()
                .map_err(|_| CryptoError::SignError)?;

            signature = ExtendedSignature {
                r: CryptoFieldElement::from_bytes_be(&r_bytes).map_err(|_| CryptoError::SignError)?,
                s: CryptoFieldElement::from_bytes_be(&s_bytes).map_err(|_| CryptoError::SignError)?,
                v: CryptoFieldElement::from_bytes_be(&v_bytes).map_err(|_| CryptoError::SignError)?,
            };

            let msg_hash_bytes: [u8; 32] = hash.try_into().map_err(|_| CryptoError::SignError)?;
            let msg_hash_felt = Felt::from_bytes_be(&msg_hash_bytes);

            Self::recover_pubkey(&msg_hash_felt, &signature)?
        } else {
            // We were given a public key directly
            let pubkey_bytes: [u8; 32] = sig_or_pubkey
                .try_into()
                .map_err(|_| CryptoError::SignError)?;
            Felt::from_bytes_be(&pubkey_bytes)
        };

        // Convert recovered public key to curve point
        let x = CurveFieldElement::from_be_bytes_mod_order(&pubkey.to_bytes_be());

        // Try both possible y values
        let y_is_odd = (signature.v.to_bytes_be()[31] & 1) == 1;
        let y = Self::compute_y_from_x(x, y_is_odd)?;

        let encoded = EncodedPoint::<StarkCurve>::from_affine_coordinates(
            &x.to_repr(),
            &y.to_repr(),
            false
        );
        let recipient_affine = AffinePoint::from_encoded_point(&encoded)
            .into_option()
            .ok_or(CryptoError::PointError)?;

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
        let ciphertext = cipher
            .encrypt(nonce, decryption_key.as_bytes())
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
     fn decrypt_key(&self, wrapped: &EncryptedData, privkey: &[u8],) -> Result<String, CryptoError> {
        if wrapped.ephemeral_pubkey.len() != 64 {
            return Err(CryptoError::PointError);
        }

        // Parse ephemeral pubkey x and y
        let eph_x = CurveFieldElement::from_be_bytes_mod_order(&wrapped.ephemeral_pubkey[0..32]);
        let eph_y = CurveFieldElement::from_be_bytes_mod_order(&wrapped.ephemeral_pubkey[32..64]);

        let encoded = EncodedPoint::<StarkCurve>::from_affine_coordinates(
            &eph_x.to_repr(),
            &eph_y.to_repr(),
            false
        );
        let eph_affine = AffinePoint::from_encoded_point(&encoded)
            .into_option()
            .ok_or(CryptoError::PointError)?;

        // Convert privkey to Scalar
        let priv_scalar = Scalar::from_be_bytes_mod_order(privkey);

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
        let plaintext = cipher
            .decrypt(nonce, wrapped.ciphertext.as_ref())
            .map_err(|_| CryptoError::SymmetricError)?;

        String::from_utf8(plaintext).map_err(|_| CryptoError::DecodeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::dotenv;
    use std::env;

    fn load_test_env() -> (Felt, Felt, String) {
        dotenv().ok();

        let privkey = env
            ::var("TEST_PRIVKEY")
            .expect("TEST_PRIVKEY must be set")
            .parse::<Felt>()
            .expect("Invalid private key format");

        let msg_hash = env
            ::var("TEST_MSG_HASH")
            .expect("TEST_MSG_HASH must be set")
            .parse::<Felt>()
            .expect("Invalid message hash format");

        let expected_pubkey = env::var("TEST_PUBKEY").expect("TEST_PUBKEY must be set");

        (privkey, msg_hash, expected_pubkey)
    }

    #[test]
fn test_sign_with_recovery() {
    let (privkey, msg_hash, expected_pubkey) = load_test_env();
    let protocol = StarknetProtocol;

    let privkey_bytes = privkey.to_bytes_be();
    let msg_hash_bytes = msg_hash.to_bytes_be();

    // Sign message (now returns r|s|v)
    let sig = protocol.sign_message(&privkey_bytes, &msg_hash_bytes).unwrap();
    println!("Signature length: {}, content: {:?}", sig.len(), sig);

    // Verify signature
    let expected_pubkey_felt = expected_pubkey.parse::<Felt>().unwrap();
    let pubkey_bytes = expected_pubkey_felt.to_bytes_be();
    println!("Expected pubkey: {:?}", pubkey_bytes);
    println!("Message hash: {:?}", msg_hash_bytes);

    let verified = protocol.verify_signature(&pubkey_bytes, &msg_hash_bytes, &sig[..64]).unwrap();
    assert!(verified, "Signature verification failed");

    // Test key encryption/decryption
    let secret_key = env::var("TEST_SECRET_KEY").unwrap_or_else(|_| "my_secret_key".to_string());

    let wrapped_key = protocol.encrypt_key(&sig, Some(&msg_hash_bytes), &secret_key).unwrap();
    println!("Wrapped Key: {:?}", wrapped_key);

    let encrypted_data = EncryptedData {
        ciphertext: wrapped_key.ciphertext,
        nonce: wrapped_key.nonce,
        ephemeral_pubkey: wrapped_key.ephemeral_pubkey,
    };

    let decrypted_key = protocol.decrypt_key(&encrypted_data, &privkey_bytes).unwrap();
    println!("Decrypted Key: {:?}", decrypted_key);
    assert_eq!(decrypted_key, secret_key);
}

}
