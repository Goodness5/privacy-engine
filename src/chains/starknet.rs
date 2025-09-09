use starknet_core::crypto::{ ecdsa_sign, ecdsa_verify, Signature };
use starknet_crypto::{ recover, ExtendedSignature, FieldElement as CryptoFieldElement };
use starknet_types_core::felt::Felt;
use crate::traits::crypto::CryptoProtocol;
use crate::types::{ CryptoError, EncryptedData };

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
    /// Parse signature from recipient identifier bytes
    fn parse_signature_from_identifier(
        recipient_identifier: &[u8]
    ) -> Result<ExtendedSignature, CryptoError> {
        if recipient_identifier.len() != 96 {
            // r(32) + s(32) + v(32)
            return Err(CryptoError::SignError);
        }

        let r_bytes: [u8; 32] = recipient_identifier[..32]
            .try_into()
            .map_err(|_| CryptoError::SignError)?;
        let s_bytes: [u8; 32] = recipient_identifier[32..64]
            .try_into()
            .map_err(|_| CryptoError::SignError)?;
        let v_bytes: [u8; 32] = recipient_identifier[64..]
            .try_into()
            .map_err(|_| CryptoError::SignError)?;

        Ok(ExtendedSignature {
            r: CryptoFieldElement::from_bytes_be(&r_bytes).map_err(|_| CryptoError::SignError)?,
            s: CryptoFieldElement::from_bytes_be(&s_bytes).map_err(|_| CryptoError::SignError)?,
            v: CryptoFieldElement::from_bytes_be(&v_bytes).map_err(|_| CryptoError::SignError)?,
        })
    }

    /// Recover public key from signature and message hash
    fn recover_pubkey_from_signature(
        recipient_identifier: &[u8],
        msg_hash: &[u8]
    ) -> Result<Felt, CryptoError> {
        let signature = Self::parse_signature_from_identifier(recipient_identifier)?;
        let msg_hash_bytes: [u8; 32] = msg_hash.try_into().map_err(|_| CryptoError::SignError)?;
        let msg_hash_felt = Felt::from_bytes_be(&msg_hash_bytes);
        Self::recover_pubkey(&msg_hash_felt, &signature)
    }

    /// Parse public key from recipient identifier bytes
    fn parse_pubkey_from_identifier(recipient_identifier: &[u8]) -> Result<Felt, CryptoError> {
        let pubkey_bytes: [u8; 32] = recipient_identifier
            .try_into()
            .map_err(|_| CryptoError::SignError)?;
        Ok(Felt::from_bytes_be(&pubkey_bytes))
    }

    /// Convert public key to curve point
    fn pubkey_to_curve_point(
        pubkey: &Felt,
        signature: &ExtendedSignature
    ) -> Result<AffinePoint, CryptoError> {
        let x = CurveFieldElement::from_be_bytes_mod_order(&pubkey.to_bytes_be());
        let y_is_odd = (signature.v.to_bytes_be()[31] & 1) == 1;
        let y = Self::compute_y_from_x(x, y_is_odd)?;

        let encoded = EncodedPoint::<StarkCurve>::from_affine_coordinates(
            &x.to_repr(),
            &y.to_repr(),
            false
        );
        AffinePoint::from_encoded_point(&encoded).into_option().ok_or(CryptoError::PointError)
    }

    /// Generate ephemeral key pair and compute shared secret
    fn generate_ephemeral_and_shared_secret(
        recipient_affine: &AffinePoint
    ) -> Result<(AffinePoint, AffinePoint), CryptoError> {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        let eph_sk = Scalar::from_be_bytes_mod_order(&random_bytes);

        let gen_affine = AffinePoint::GENERATOR;
        let gen_proj: ProjectivePoint = gen_affine.into();
        let eph_proj = gen_proj * eph_sk;
        let eph_affine: AffinePoint = eph_proj.into();

        // Shared secret = recipient_affine * eph_sk
        let shared_proj = ProjectivePoint::from(*recipient_affine) * eph_sk;
        let shared_affine: AffinePoint = shared_proj.into();

        Ok((eph_affine, shared_affine))
    }

    /// Derive AES key from shared secret
    fn derive_aes_key(shared_affine: &AffinePoint) -> Result<[u8; 32], CryptoError> {
        let encoded_shared = shared_affine.to_encoded_point(false);
        let shared_x = encoded_shared.x().ok_or(CryptoError::PointError)?;
        let mut h = Sha256::new();
        h.update(shared_x.as_slice());
        let aes_key_bytes = h.finalize();
        Ok(aes_key_bytes.into())
    }

    /// Encrypt data with AES-GCM and serialize ephemeral public key
    fn encrypt_with_aes_and_serialize_ephemeral(
        key: &[u8],
        aes_key: &Key<Aes256Gcm>,
        eph_affine: &AffinePoint
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = OsRng;
        let cipher = Aes256Gcm::new(aes_key);
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, key).map_err(|_| CryptoError::SymmetricError)?;

        // Serialize ephemeral public key (uncompressed: x || y)
        let encoded_eph = eph_affine.to_encoded_point(false);
        let eph_x = encoded_eph.x().ok_or(CryptoError::PointError)?;
        let eph_y = encoded_eph.y().ok_or(CryptoError::PointError)?;
        let mut eph_bytes = Vec::with_capacity(64);
        eph_bytes.extend_from_slice(eph_x.as_slice());
        eph_bytes.extend_from_slice(eph_y.as_slice());

        Ok((ciphertext, nonce_bytes.to_vec(), eph_bytes))
    }

    fn encrypt_with_signature(
        &self,
        sig_bytes: &[u8], // r||s||v (96 bytes)
        msg_hash: &[u8], // 32 bytes
        key: &[u8]
    ) -> Result<EncryptedData, CryptoError> {
        // First perform standard ECDH to wrap the key → DEK1 blob
        let pubkey = Self::recover_pubkey_from_signature(sig_bytes, msg_hash)?;
        let signature = Self::parse_signature_from_identifier(sig_bytes)?;
        let recipient_affine = Self::pubkey_to_curve_point(&pubkey, &signature)?;
        let (eph_affine, shared_affine) = Self::generate_ephemeral_and_shared_secret(
            &recipient_affine
        )?;
        let aes_key_bytes = Self::derive_aes_key(&shared_affine)?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        let (inner_ct, inner_nonce, inner_eph_pub) = Self::encrypt_with_aes_and_serialize_ephemeral(
            key,
            &aes_key,
            &eph_affine
        )?;

        // Serialize DEK1 = nonce || eph_pubkey || ciphertext
        let mut dek1_blob = Vec::with_capacity(12 + inner_eph_pub.len() + inner_ct.len());
        dek1_blob.extend_from_slice(&inner_nonce);
        dek1_blob.extend_from_slice(&inner_eph_pub);
        dek1_blob.extend_from_slice(&inner_ct);

        // Now derive DEK2 from msg_hash + signature and wrap DEK1
        let dek2 = Self::derive_dek2_from_sig(msg_hash, sig_bytes);
        let outer = Self::wrap_with_dek2(&dek1_blob, &dek2)?;

        if outer.len() < 12 {
            return Err(CryptoError::SymmetricError);
        }
        let (outer_nonce, outer_ct) = outer.split_at(12);

        Ok(EncryptedData {
            ciphertext: outer_ct.to_vec(),
            nonce: outer_nonce.to_vec(),
            ephemeral_pubkey: Vec::new(),
        })
    }

    /// Encrypt key using public key directly (for clients that can provide public keys)
    fn encrypt_with_public_key(
        &self,
        public_key: &[u8],
        key: &[u8]
    ) -> Result<EncryptedData, CryptoError> {
        // Parse public key from bytes
        let pubkey = Self::parse_pubkey_from_identifier(public_key)?;

        // Create a dummy signature for curve point conversion (v=0 for even y, v=1 for odd y)
        let signature = ExtendedSignature {
            r: CryptoFieldElement::ZERO,
            s: CryptoFieldElement::ZERO,
            v: CryptoFieldElement::ZERO, // Will be determined during curve point conversion
        };

        // Convert public key to curve point
        let recipient_affine = Self::pubkey_to_curve_point(&pubkey, &signature)?;

        // Generate ephemeral key pair and compute shared secret
        let (eph_affine, shared_affine) = Self::generate_ephemeral_and_shared_secret(
            &recipient_affine
        )?;

        // Derive AES key from shared secret
        let aes_key_bytes = Self::derive_aes_key(&shared_affine)?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        // Encrypt data and serialize ephemeral public key
        let (ciphertext, nonce, ephemeral_pubkey) = Self::encrypt_with_aes_and_serialize_ephemeral(
            key,
            &aes_key,
            &eph_affine
        )?;

        Ok(EncryptedData {
            ciphertext,
            nonce,
            ephemeral_pubkey,
        })
    }

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

    /// Derive DEK2 from (msg_hash + signature)
    pub fn derive_dek2_from_sig(msg_hash: &[u8], sig: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(msg_hash);
        hasher.update(sig);
        let digest = hasher.finalize();
        let mut dek2 = [0u8; 32];
        dek2.copy_from_slice(&digest[..32]);
        dek2
    }

    /// Wrap DEK1 (already encrypted with ECDH) again under DEK2
    pub fn wrap_with_dek2(dek1_cipher: &[u8], dek2: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(dek2).map_err(|_| CryptoError::SymmetricError)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_obj = Nonce::from_slice(&nonce);

        let ct = cipher.encrypt(nonce_obj, dek1_cipher).map_err(|_| CryptoError::SymmetricError)?;

        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Unwrap DEK1 by first deriving DEK2 from sig+msg, then decrypting
    pub fn unwrap_with_dek2(
        wrapped: &[u8],
        msg_hash: &[u8],
        sig: &[u8]
    ) -> Result<Vec<u8>, CryptoError> {
        if wrapped.len() < 12 {
            return Err(CryptoError::SymmetricError);
        }
        let dek2 = Self::derive_dek2_from_sig(msg_hash, sig);

        let (nonce_bytes, ct) = wrapped.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&dek2).map_err(|_| CryptoError::SymmetricError)?;
        let nonce_obj = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce_obj, ct).map_err(|_| CryptoError::SymmetricError)
    }

    /// Generate a fresh random challenge (32 bytes). Server should store and mark single-use.
    pub fn generate_challenge(&self) -> Result<Vec<u8>, CryptoError> {
        let mut rng = OsRng;
        let mut challenge = vec![0u8; 32];
        rng.fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Encrypt `key` with DEK2 derived from (challenge || signature).
    /// - challenge: the fresh nonce server generated and sent to client
    /// - signature_bytes: bytes returned by wallet signing challenge (e.g. r||s||v or r||s)
    /// Returns EncryptedData with aes-gcm outer layer: { ciphertext, nonce, ephemeral_pubkey = [] }
    pub fn encrypt_with_signature_challenge(
        &self,
        challenge: &[u8],
        signature_bytes: &[u8],
        key: &[u8]
    ) -> Result<EncryptedData, CryptoError> {
        if challenge.is_empty() || signature_bytes.is_empty() {
            return Err(CryptoError::SignError);
        }

        // Derive DEK2 = SHA256(challenge || signature)
        let mut h = Sha256::new();
        h.update(challenge);
        h.update(signature_bytes);
        let dek2_bytes = h.finalize();

        // AES-GCM encrypt `key` with dek2_bytes
        let aes_key = Key::<Aes256Gcm>::from_slice(&dek2_bytes[..]);
        let cipher = Aes256Gcm::new(aes_key);

        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, key).map_err(|_| CryptoError::SymmetricError)?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            ephemeral_pubkey: Vec::new(), // outer layer — no ephemeral pubkey
        })
    }

    /// Decrypt the outer signature-derived layer.
    /// - `wrapped` is the EncryptedData returned by encrypt_with_signature_challenge,
    /// - `challenge` and `signature_bytes` must be identical to those used during encryption.
    /// Returns the plaintext `key` on success.
    pub fn decrypt_with_signature_challenge(
        &self,
        wrapped: &EncryptedData,
        challenge: &[u8],
        signature_bytes: &[u8]
    ) -> Result<Vec<u8>, CryptoError> {
        if wrapped.nonce.len() != 12 {
            return Err(CryptoError::PointError);
        }
        if challenge.is_empty() || signature_bytes.is_empty() {
            return Err(CryptoError::SignError);
        }

        // Derive DEK2 = SHA256(challenge || signature)
        let mut h = Sha256::new();
        h.update(challenge);
        h.update(signature_bytes);
        let dek2_bytes = h.finalize();

        let aes_key = Key::<Aes256Gcm>::from_slice(&dek2_bytes[..]);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&wrapped.nonce);

        let plaintext = cipher
            .decrypt(nonce, wrapped.ciphertext.as_ref())
            .map_err(|_| CryptoError::SymmetricError)?;

        Ok(plaintext)
    }


     pub fn decrypt_key_with_signature(
        &self,
        wrapped: &EncryptedData,
        privkey: &[u8],
        signature: &[u8],
        msg_hash: &[u8]
    ) -> Result<Vec<u8>, CryptoError> {
        // First, unwrap the outer layer using DEK2 derived from signature and message hash
        // Reconstruct the full wrapped data: nonce || ciphertext
        let mut full_wrapped = Vec::with_capacity(wrapped.nonce.len() + wrapped.ciphertext.len());
        full_wrapped.extend_from_slice(&wrapped.nonce);
        full_wrapped.extend_from_slice(&wrapped.ciphertext);
        let dek1_blob = Self::unwrap_with_dek2(&full_wrapped, msg_hash, signature)?;
        
        // Extract components from DEK1 blob: nonce || eph_pubkey || ciphertext
        if dek1_blob.len() < 12 {
            return Err(CryptoError::SymmetricError);
        }
        let (inner_nonce, rest) = dek1_blob.split_at(12);
        
        if rest.len() < 64 {
            return Err(CryptoError::SymmetricError);
        }
        let (inner_eph_pub, inner_ciphertext) = rest.split_at(64);
        
        // Parse ephemeral pubkey from DEK1
        let eph_x = CurveFieldElement::from_be_bytes_mod_order(&inner_eph_pub[0..32]);
        let eph_y = CurveFieldElement::from_be_bytes_mod_order(&inner_eph_pub[32..64]);

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
        h.update(shared_x.as_slice());
        let aes_key_bytes = h.finalize();
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        // Decrypt the inner ciphertext
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(inner_nonce);
        let plaintext = cipher
            .decrypt(nonce, inner_ciphertext)
            .map_err(|_| CryptoError::SymmetricError)?;

        Ok(plaintext)
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
        let pub_x_bytes: [u8; 32] = pub_x
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::SignError)?;
        let pubkey_felt = Felt::from_bytes_be(&pub_x_bytes);

        // Compute possible public keys from signature
        let r_fe = CryptoFieldElement::from_bytes_be(&signature.r.to_bytes_be()).map_err(
            |_| CryptoError::SignError
        )?;
        let s_fe = CryptoFieldElement::from_bytes_be(&signature.s.to_bytes_be()).map_err(
            |_| CryptoError::SignError
        )?;
        let msg_fe = CryptoFieldElement::from_bytes_be(&msg_hash_felt.to_bytes_be()).map_err(
            |_| CryptoError::SignError
        )?;

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
        recipient_identifier: &[u8],
        msg_hash: Option<&[u8]>,
        key: &[u8]
    ) -> Result<EncryptedData, CryptoError> {
        match msg_hash {
            Some(hash) => {
                // We were given a signature and message hash - use signature-based encryption
                self.encrypt_with_signature(recipient_identifier, hash, key)
            }
            None => {
                // We were given a public key directly - use public key encryption
                self.encrypt_with_public_key(recipient_identifier, key)
            }
        }
    }

    /// Decrypt the wrapped key using the private key
    fn decrypt_key(&self, wrapped: &EncryptedData, privkey: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Check if this is signature-based encryption (empty ephemeral_pubkey)
        if wrapped.ephemeral_pubkey.is_empty() {
            // This is signature-based encryption - we need the signature and message hash
            // For now, we'll return an error indicating this method doesn't support signature-based decryption
            // The caller should use a different method that provides the signature and message hash
            return Err(CryptoError::PointError);
        }

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
        h.update(shared_x.as_slice());
        let aes_key_bytes = h.finalize();
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        // Decrypt
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&wrapped.nonce);
        let plaintext = cipher
            .decrypt(nonce, wrapped.ciphertext.as_ref())
            .map_err(|_| CryptoError::SymmetricError)?;

        Ok(plaintext)
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

        let verified = protocol
            .verify_signature(&pubkey_bytes, &msg_hash_bytes, &sig[..64])
            .unwrap();
        assert!(verified, "Signature verification failed");

        // Test key encryption/decryption
        let secret_key = env
            ::var("TEST_SECRET_KEY")
            .unwrap_or_else(|_| "my_secret_key".to_string());

        let wrapped_key = protocol
            .encrypt_key(&sig, Some(&msg_hash_bytes), secret_key.as_bytes())
            .unwrap();
        println!("Wrapped Key (signature): {:?}", wrapped_key);

        let encrypted_data = EncryptedData {
            ciphertext: wrapped_key.ciphertext,
            nonce: wrapped_key.nonce,
            ephemeral_pubkey: wrapped_key.ephemeral_pubkey,
        };

        let decrypted_key = protocol.decrypt_key_with_signature(&encrypted_data, &privkey_bytes, &sig, &msg_hash_bytes).unwrap();
        println!("Decrypted Key: {:?}", decrypted_key);
        assert_eq!(decrypted_key, secret_key.as_bytes());
    }

    #[test]
    fn test_public_key_encryption() {
        let (privkey, _msg_hash, expected_pubkey) = load_test_env();
        let protocol = StarknetProtocol;

        let privkey_bytes = privkey.to_bytes_be();
        let expected_pubkey_felt = expected_pubkey.parse::<Felt>().unwrap();
        let pubkey_bytes = expected_pubkey_felt.to_bytes_be();

        // Test key encryption/decryption using public key directly
        let secret_key = env
            ::var("TEST_SECRET_KEY")
            .unwrap_or_else(|_| "my_secret_key".to_string());

        // Encrypt using public key (no signature/message hash)
        let wrapped_key = protocol
            .encrypt_key(&pubkey_bytes, None, secret_key.as_bytes())
            .unwrap();
        println!("Wrapped Key (public key): {:?}", wrapped_key);

        let encrypted_data = EncryptedData {
            ciphertext: wrapped_key.ciphertext,
            nonce: wrapped_key.nonce,
            ephemeral_pubkey: wrapped_key.ephemeral_pubkey,
        };

        let decrypted_key = protocol.decrypt_key(&encrypted_data, &privkey_bytes).unwrap();
        println!("Decrypted Key (public key): {:?}", decrypted_key);
        assert_eq!(decrypted_key, secret_key.as_bytes());
    }
}
