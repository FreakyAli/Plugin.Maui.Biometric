    namespace Plugin.Maui.Biometric;

    public interface ISecureBiometric
    {
        /// <summary>
        /// Create a hardware-backed key for future cryptographic operations.
        /// Android: KeyPair / symmetric key in Keystore / StrongBox
        /// iOS/macOS: SecKeyCreateRandomKey (Secure Enclave / Keychain)
        /// Windows: KeyCredentialManager / DPAPI key
        /// </summary>
        Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options);

        /// <summary>
        /// Delete a key from the keystore / Secure Enclave.
        /// Android: KeyStore.deleteEntry
        /// iOS/macOS: SecItemDelete
        /// Windows: KeyCredentialManager.DeleteAsync
        /// </summary>
        Task<KeyOperationResult> DeleteKeyAsync(string keyId);

        /// <summary>
        /// Check if a key exists.
        /// Android: KeyStore.containsAlias
        /// iOS/macOS: SecItemCopyMatching
        /// Windows: KeyCredentialManager.OpenAsync
        /// </summary>
        Task<KeyOperationResult> KeyExistsAsync(string keyId);

        /// <summary>
        /// Encrypt input data using a hardware-backed key.
        /// Android: Cipher.getInstance("AES/GCM/NoPadding") with KeyStore key
        /// iOS/macOS: SecKeyCreateEncryptedData
        /// Windows: CryptographicEngine.EncryptAsync
        /// </summary>
        Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token);

        /// <summary>
        /// Decrypt input data using a hardware-backed key.
        /// Android: Cipher.doFinal with KeyStore key
        /// iOS/macOS: SecKeyCreateDecryptedData
        /// Windows: CryptographicEngine.DecryptAsync
        /// </summary>
        Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token);

        /// <summary>
        /// Sign input data using a hardware-backed key.
        /// Android: Signature.getInstance("SHA256withRSA") with KeyStore key
        /// iOS/macOS: SecKeyCreateSignature
        /// Windows: CryptographicEngine.SignAsync
        /// </summary>
        Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token);

        /// <summary>
        /// Verify signature against input data using a hardware-backed key.
        /// Android: Signature.verify
        /// iOS/macOS: SecKeyVerifySignature
        /// Windows: CryptographicEngine.VerifySignatureAsync
        /// </summary>
        Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token);

        /// <summary>
        /// Compute a MAC (message authentication code) on input data using a hardware-backed key.
        /// Android: Mac.getInstance("HmacSHA256") with KeyStore key
        /// iOS/macOS: CCHmac or SecKey operations
        /// Windows: CryptographicEngine.SignAsync with HMAC key
        /// </summary>
        Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token);
    }