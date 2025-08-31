namespace Plugin.Maui.Biometric;

public sealed class CryptoKeyOptions
{
    /// <summary>
    /// Algorithm to be used for the key. Defaults to AES.
    /// </summary>
    public KeyAlgorithm Algorithm { get; set; } = KeyAlgorithm.Aes;

    /// <summary>
    /// Intended operations for the key (Encrypt, Decrypt, Sign, Verify).
    /// </summary>
    public CryptoOperation Operation { get; set; }

    /// <summary>
    /// Key size in bits. Default: 256 (AES-256).
    /// </summary>
    public int KeySize { get; set; } = 256;

    /// <summary>
    /// Require biometric or device authentication for usage.
    /// </summary>
    public bool RequireUserAuthentication { get; set; } = true;

    /// <summary>
    /// Block mode (CBC, GCM, etc). Default: GCM.
    /// </summary>
    public BlockMode BlockMode { get; set; } = BlockMode.Gcm;

    /// <summary>
    /// Padding scheme. Default: None.
    /// </summary>
   public Padding Padding { get; set; } = Padding.None;

    /// <summary>
    /// Digest algorithm (for signatures). Default: SHA256.
    /// </summary>
    public Digest Digest { get; set; } = Digest.Sha256;
}