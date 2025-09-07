use wasm_bindgen::prelude::*;
use serde_json;
use crate::encrypt::encrypt_message;
use crate::decrypt::decrypt_shared_secret;
use crate::types::{RecipientInfo, Protocol};

// Import the `console.log` function from the `console` module
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Define a macro to make console.log work like println!
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// Simple WASM wrapper for encrypt_message
#[wasm_bindgen]
pub fn encrypt_message_wasm(
    message: &[u8],
    recipients_json: &str
) -> Result<String, JsValue> {
    console_log!("Starting encryption");
    
    // Parse recipients from JSON
    let recipients: Vec<RecipientInfo> = serde_json::from_str(recipients_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse recipients: {}", e)))?;
    
    console_log!("Encrypting message of {} bytes for {} recipients", message.len(), recipients.len());
    
    // Call the existing encrypt_message function
    let result = encrypt_message(message, recipients)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // Serialize result to JSON
    let result_json = serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))?;
    
    console_log!("Encryption completed successfully");
    Ok(result_json)
}

/// Simple WASM wrapper for decrypt_shared_secret
#[wasm_bindgen]
pub fn decrypt_shared_secret_wasm(
    private_key: &[u8],
    encrypted_key_json: &str
) -> Result<Vec<u8>, JsValue> {
    console_log!("Starting key decryption");
    
    // Parse encrypted key from JSON
    let encrypted_key: crate::types::RecipientEncryptedKey = serde_json::from_str(encrypted_key_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse encrypted key: {}", e)))?;
    
    // Call the existing decrypt_shared_secret function
    let result = decrypt_shared_secret(private_key, &encrypted_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    console_log!("Key decryption completed successfully");
    Ok(result)
}

/// Get supported protocols as JSON
#[wasm_bindgen]
pub fn get_supported_protocols() -> String {
    let protocols = vec!["starknet", "x25519"];
    serde_json::to_string(&protocols).unwrap_or_else(|_| "[]".to_string())
}

/// Validate a public key for a given protocol
#[wasm_bindgen]
pub fn validate_public_key(pubkey: &[u8], protocol: &str) -> Result<bool, JsValue> {
    let protocol_enum = match protocol.to_lowercase().as_str() {
        "starknet" => Protocol::Starknet,
        "x25519" => Protocol::X25519,
        _ => return Err(JsValue::from_str(&format!("Unknown protocol: {}", protocol))),
    };
    
    match protocol_enum {
        Protocol::Starknet => Ok(pubkey.len() == 32),
        Protocol::X25519 => Ok(pubkey.len() == 32),
    }
}

/// Get protocol information as JSON
#[wasm_bindgen]
pub fn get_protocol_info(protocol: &str) -> Result<String, JsValue> {
    let info = match protocol.to_lowercase().as_str() {
        "starknet" => serde_json::json!({
            "name": "Starknet",
            "curve": "Stark Curve",
            "keySize": 32,
            "supportsSigning": true
        }),
        "x25519" => serde_json::json!({
            "name": "X25519",
            "curve": "Curve25519",
            "keySize": 32,
            "supportsSigning": false
        }),
        _ => return Err(JsValue::from_str(&format!("Unknown protocol: {}", protocol))),
    };
    
    Ok(info.to_string())
}

// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    console_log!("Privacy Engine WASM module initialized");
}