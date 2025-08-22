namespace Plugin.Maui.Biometric;

public interface IBiometricCrypto
{
    /// <summary>
    /// Create a hardware-backed key for future cryptographic operations.
    /// Android: KeyPair / symmetric key in Keystore / StrongBox
    /// iOS/macOS: SecKeyCreateRandomKey (Secure Enclave / Keychain)
    /// Windows: KeyCredentialManager / DPAPI key
    /// </summary>
    Task CreateKeyAsync(string keyId, CryptoKeyOptions options, CancellationToken token = default);

    /// <summary>
    /// Encrypt input data using a hardware-backed key.
    /// </summary>
    Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token = default);

    /// <summary>
    /// Decrypt input data using a hardware-backed key.
    /// </summary>
    Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token = default);

    /// <summary>
    /// Sign input data using a hardware-backed key.
    /// </summary>
    Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token = default);

    /// <summary>
    /// Verify signature against input data using a hardware-backed key.
    /// </summary>
    Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token = default);

    /// <summary>
    /// Compute a MAC (message authentication code) on input data using a hardware-backed key.
    /// </summary>
    Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token = default);

    /// <summary>
    /// Delete a key from the keystore / Secure Enclave.
    /// </summary>
    Task DeleteKeyAsync(string keyId);

    /// <summary>
    /// Check if a key exists.
    /// </summary>
    Task<bool> KeyExistsAsync(string keyId);
}


public sealed class SecureCryptoResponse
{
    public bool WasSuccessful { get; set; }
    public byte[]? OutputData { get; set; }
    public string? ErrorMessage { get; set; }
}

public class CryptoKeyOptions
{
    /// <summary>
    /// Operation type (Encrypt, Decrypt, Sign, Verify, MAC)
    /// </summary>
    public CryptoOperation Operation { get; set; }

    /// <summary>
    /// Optional algorithm (e.g., AES, RSA, ECDSA)
    /// </summary>
    public string? Algorithm { get; set; }

    /// <summary>
    /// Optional key size in bits
    /// </summary>
    public int? KeySize { get; set; }

    /// <summary>
    /// Optional flag for requiring biometric authentication to use the key
    /// </summary>
    public bool RequireUserAuthentication { get; set; } = true;
}

public enum CryptoOperation
{
    Sign,
    Verify,
    Encrypt,
    Decrypt
}