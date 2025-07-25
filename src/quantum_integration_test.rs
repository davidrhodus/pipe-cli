#[cfg(test)]
mod quantum_integration_tests {
    use crate::quantum::{sign_and_encrypt, decrypt_and_verify};
    use crate::quantum_keyring::{generate_quantum_keypair, save_quantum_keypair, load_quantum_keypair, delete_quantum_keypair};
    use crate::encryption::{encrypt_data, decrypt_data, derive_key_from_password};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_quantum_upload_download_workflow() {
        // Create a temporary directory for test files
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let test_data = b"This is a test file for quantum encryption workflow";
        fs::write(&test_file, test_data).unwrap();

        // Generate quantum keys
        let file_id = "workflow_test.txt";
        let keypair = generate_quantum_keypair(file_id).unwrap();
        
        // Save keys
        save_quantum_keypair(&keypair).unwrap();
        
        // Simulate upload: sign and encrypt
        let encrypted = sign_and_encrypt(
            test_data,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        // Write encrypted file
        let encrypted_file = temp_dir.path().join("test.qenc");
        fs::write(&encrypted_file, &encrypted).unwrap();
        
        // Simulate download: load keys and decrypt
        let loaded_keypair = load_quantum_keypair(file_id).unwrap();
        let encrypted_data = fs::read(&encrypted_file).unwrap();
        
        let decrypted = decrypt_and_verify(
            &encrypted_data,
            &loaded_keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(decrypted.data, test_data);
        assert_eq!(decrypted.signer_public_key, keypair.dilithium_public);
        
        // Clean up
        delete_quantum_keypair(file_id).unwrap();
    }

    #[test]
    fn test_quantum_with_different_file_sizes() {
        let test_sizes = vec![
            0,          // Empty file
            100,        // Small file
            1024,       // 1KB
            10240,      // 10KB
            102400,     // 100KB
            1048576,    // 1MB
        ];
        
        for size in test_sizes {
            let test_data = vec![b'A'; size];
            let file_id = format!("size_test_{}.dat", size);
            
            // Generate keys
            let keypair = generate_quantum_keypair(&file_id).unwrap();
            
            // Encrypt
            let encrypted = sign_and_encrypt(
                &test_data,
                &keypair.dilithium_secret,
                &keypair.dilithium_public,
                &keypair.kyber_public,
            ).unwrap();
            
            // Verify overhead
            assert!(encrypted.len() > test_data.len() + 8000, "Expected ~8KB overhead for size {}", size);
            
            // Decrypt
            let decrypted = decrypt_and_verify(
                &encrypted,
                &keypair.kyber_secret,
            ).unwrap();
            
            assert_eq!(decrypted.data.len(), size, "Size mismatch for {}", size);
            assert_eq!(decrypted.data, test_data, "Data mismatch for size {}", size);
        }
    }

    #[test]
    fn test_quantum_key_persistence() {
        let file_id = "persistence_test.txt";
        
        // Generate and save keys
        let original_keypair = generate_quantum_keypair(file_id).unwrap();
        save_quantum_keypair(&original_keypair).unwrap();
        
        // Load keys multiple times
        for _ in 0..5 {
            let loaded = load_quantum_keypair(file_id).unwrap();
            assert_eq!(loaded.kyber_public, original_keypair.kyber_public);
            assert_eq!(loaded.kyber_secret, original_keypair.kyber_secret);
            assert_eq!(loaded.dilithium_public, original_keypair.dilithium_public);
            assert_eq!(loaded.dilithium_secret, original_keypair.dilithium_secret);
        }
        
        // Delete and verify it's gone
        delete_quantum_keypair(file_id).unwrap();
        assert!(load_quantum_keypair(file_id).is_err());
    }

    #[test]
    fn test_quantum_signature_tampering_detection() {
        let test_data = b"Important message that must not be tampered with";
        let file_id = "tamper_test.txt";
        
        // Generate keys
        let keypair = generate_quantum_keypair(file_id).unwrap();
        
        // Sign and encrypt
        let encrypted = sign_and_encrypt(
            test_data,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        // Tamper with the encrypted data
        let mut tampered = encrypted.clone();
        tampered[100] ^= 0xFF; // Flip some bits
        
        // Try to decrypt tampered data - should fail
        let result = decrypt_and_verify(
            &tampered,
            &keypair.kyber_secret,
        );
        
        // The exact error depends on where we tampered, but it should fail
        assert!(result.is_err(), "Tampered data should fail verification");
    }

    #[test]
    fn test_quantum_wrong_key_rejection() {
        let test_data = b"Secret data";
        
        // Generate two different keypairs
        let keypair1 = generate_quantum_keypair("key1").unwrap();
        let keypair2 = generate_quantum_keypair("key2").unwrap();
        
        // Encrypt with keypair1
        let encrypted = sign_and_encrypt(
            test_data,
            &keypair1.dilithium_secret,
            &keypair1.dilithium_public,
            &keypair1.kyber_public,
        ).unwrap();
        
        // Try to decrypt with keypair2 - should fail
        let result = decrypt_and_verify(
            &encrypted,
            &keypair2.kyber_secret,
        );
        
        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    #[test]
    fn test_quantum_plus_password_double_encryption() {
        let test_data = b"Ultra secret data needing double protection";
        let password = "strong_password_123!@#";
        let salt = b"test-salt-for-quantum";
        
        // Generate quantum keys
        let keypair = generate_quantum_keypair("double_encrypted").unwrap();
        
        // First layer: password encryption
        let password_key = derive_key_from_password(password, salt).unwrap();
        let (password_encrypted, nonce) = encrypt_data(test_data, &password_key).unwrap();
        
        // Combine nonce and encrypted data
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&password_encrypted);
        
        // Second layer: quantum encryption
        let quantum_encrypted = sign_and_encrypt(
            &combined,
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        // Decrypt: quantum layer first
        let quantum_decrypted = decrypt_and_verify(
            &quantum_encrypted,
            &keypair.kyber_secret,
        ).unwrap();
        
        // Extract nonce and decrypt password layer
        assert!(quantum_decrypted.data.len() >= 12, "Not enough data for nonce");
        let (nonce_bytes, encrypted_data) = quantum_decrypted.data.split_at(12);
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce_bytes);
        
        let final_decrypted = decrypt_data(
            encrypted_data,
            &password_key,
            &nonce_array,
        ).unwrap();
        
        assert_eq!(final_decrypted, test_data);
    }

    #[test]
    fn test_concurrent_quantum_operations() {
        use std::thread;
        use std::sync::Arc;
        
        let data = Arc::new(vec![b'X'; 1000]);
        let mut handles = vec![];
        
        // Spawn multiple threads doing quantum operations
        for i in 0..5 {
            let data_clone = Arc::clone(&data);
            let handle = thread::spawn(move || {
                let file_id = format!("concurrent_test_{}", i);
                let keypair = generate_quantum_keypair(&file_id).unwrap();
                
                // Encrypt
                let encrypted = sign_and_encrypt(
                    &data_clone,
                    &keypair.dilithium_secret,
                    &keypair.dilithium_public,
                    &keypair.kyber_public,
                ).unwrap();
                
                // Save keys
                save_quantum_keypair(&keypair).unwrap();
                
                // Decrypt
                let decrypted = decrypt_and_verify(
                    &encrypted,
                    &keypair.kyber_secret,
                ).unwrap();
                
                assert_eq!(decrypted.data, *data_clone);
                
                // Clean up
                delete_quantum_keypair(&file_id).unwrap();
            });
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_quantum_error_handling() {
        // Test loading non-existent key
        assert!(load_quantum_keypair("non_existent_key").is_err());
        
        // Test invalid key data
        let invalid_public_key = vec![0xFF; 32]; // Too short for Kyber public key
        let result = sign_and_encrypt(
            b"test",
            &vec![0; 4896], // Dilithium secret key size
            &vec![0; 2592], // Dilithium public key size  
            &invalid_public_key,
        );
        assert!(result.is_err());
        
        // Test empty data encryption
        let keypair = generate_quantum_keypair("empty_test").unwrap();
        let encrypted = sign_and_encrypt(
            b"",
            &keypair.dilithium_secret,
            &keypair.dilithium_public,
            &keypair.kyber_public,
        ).unwrap();
        
        let decrypted = decrypt_and_verify(
            &encrypted,
            &keypair.kyber_secret,
        ).unwrap();
        
        assert_eq!(decrypted.data, b"");
    }
} 