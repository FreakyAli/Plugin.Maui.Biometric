namespace Plugin.Maui.Biometric;

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
