use anyhow::{anyhow, Result};
use pqcrypto_mlkem::mlkem1024 as kyber1024;
use pqcrypto_mldsa::mldsa87 as dilithium5;
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Quantum key pair storage
#[derive(Serialize, Deserialize)]
pub struct QuantumKeyPair {
    /// Kyber public key for encryption
    pub kyber_public: Vec<u8>,
    /// Kyber secret key for decryption
    pub kyber_secret: Vec<u8>,
    /// Dilithium public key for verification
    pub dilithium_public: Vec<u8>,
    /// Dilithium secret key for signing
    pub dilithium_secret: Vec<u8>,
    /// File identifier (hash or name)
    pub file_id: String,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Get the quantum keyring directory
fn get_keyring_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
    let keyring_dir = home.join(".pipe-cli").join("quantum-keys");
    if !keyring_dir.exists() {
        fs::create_dir_all(&keyring_dir)?;
    }
    Ok(keyring_dir)
}

/// Generate a new quantum key pair
pub fn generate_quantum_keypair(file_id: &str) -> Result<QuantumKeyPair> {
    // Generate Kyber keypair for encryption
    let (kyber_public, kyber_secret) = kyber1024::keypair();
    
    // Generate Dilithium keypair for signing
    let (dilithium_public, dilithium_secret) = dilithium5::keypair();
    
    Ok(QuantumKeyPair {
        kyber_public: kyber_public.as_bytes().to_vec(),
        kyber_secret: kyber_secret.as_bytes().to_vec(),
        dilithium_public: dilithium_public.as_bytes().to_vec(),
        dilithium_secret: dilithium_secret.as_bytes().to_vec(),
        file_id: file_id.to_string(),
        created_at: chrono::Utc::now(),
    })
}

/// Save quantum keypair to keyring
pub fn save_quantum_keypair(keypair: &QuantumKeyPair) -> Result<()> {
    let keyring_dir = get_keyring_dir()?;
    let key_file = keyring_dir.join(format!("{}.quantum", keypair.file_id));
    
    let json = serde_json::to_string_pretty(keypair)?;
    fs::write(&key_file, json)?;
    
    println!("Quantum keys saved to: {}", key_file.display());
    Ok(())
}

/// Load quantum keypair from keyring
pub fn load_quantum_keypair(file_id: &str) -> Result<QuantumKeyPair> {
    let keyring_dir = get_keyring_dir()?;
    let key_file = keyring_dir.join(format!("{}.quantum", file_id));
    
    if !key_file.exists() {
        return Err(anyhow!("Quantum key not found for file: {}", file_id));
    }
    
    let json = fs::read_to_string(&key_file)?;
    let keypair: QuantumKeyPair = serde_json::from_str(&json)?;
    Ok(keypair)
}

/// List all quantum keys in the keyring
#[allow(dead_code)]
pub fn list_quantum_keys() -> Result<Vec<String>> {
    let keyring_dir = get_keyring_dir()?;
    let mut keys = Vec::new();
    
    for entry in fs::read_dir(keyring_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("quantum") {
            if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                keys.push(file_stem.to_string());
            }
        }
    }
    
    Ok(keys)
}

/// Delete a quantum keypair
#[allow(dead_code)]
pub fn delete_quantum_keypair(file_id: &str) -> Result<()> {
    let keyring_dir = get_keyring_dir()?;
    let key_file = keyring_dir.join(format!("{}.quantum", file_id));
    
    if key_file.exists() {
        fs::remove_file(&key_file)?;
        println!("Quantum key deleted for: {}", file_id);
    }
    
    Ok(())
} 