namespace Plugin.Maui.Biometric;

/// <summary>
/// Configuration options for creating a hardware-backed cryptographic key.
/// <para>
/// <b>Platform-specific key size and algorithm constraints:</b>
/// <list type="bullet">
///   <item><b>Android StrongBox:</b> Only supports AES 128/256, RSA 2048, and EC P-256.
///     Larger keys (RSA 3072/4096, EC P-384/P-521) fall back to TEE or software.</item>
///   <item><b>Apple Secure Enclave:</b> Only supports EC P-256.
///     RSA and larger EC keys are stored in the Keychain (not Secure Enclave).</item>
///   <item><b>Windows:</b> RSA/EC keys support signing only (not encrypt/decrypt).
///     TPM 1.2 devices only support RSA; TPM 2.0 supports RSA + EC.</item>
/// </list>
/// </para>
/// </summary>
public sealed class CryptoKeyOptions
{
    /// <summary>
    /// Algorithm to be used for the key. Defaults to AES.
    /// <para><b>Android:</b> AES, RSA, and EC are supported.</para>
    /// <para><b>iOS/macOS:</b> AES (Keychain), EC P-256 (Secure Enclave), RSA (Keychain).</para>
    /// <para><b>Windows:</b> AES (PasswordVault), RSA/EC (Windows Hello — signing only).</para>
    /// </summary>
    public KeyAlgorithm Algorithm { get; set; } = KeyAlgorithm.Aes;

    /// <summary>
    /// Intended operations for the key (Encrypt, Decrypt, Sign, Verify).
    /// <para><b>Note:</b> EC keys cannot be used for Encrypt/Decrypt — use Sign/Verify.
    /// AES keys cannot be used for Sign/Verify — use Encrypt/Decrypt.
    /// Windows RSA/EC keys only support Sign/Verify.</para>
    /// </summary>
    public CryptoOperation Operation { get; set; } = CryptoOperation.Encrypt | CryptoOperation.Decrypt;

    /// <summary>
    /// Key size in bits. Default: 256 (AES-256).
    /// <para>Valid sizes: AES: 128, 192, 256. RSA: 2048, 3072, 4096. EC: 256, 384, 521.</para>
    /// <para><b>Android StrongBox:</b> Limited to AES 128/256, RSA 2048, EC 256.</para>
    /// <para><b>Apple Secure Enclave:</b> Only EC 256 is Secure Enclave-backed.</para>
    /// </summary>
    public int KeySize { get; set; } = 256;

    /// <summary>
    /// Require biometric or device authentication for usage.
    /// When <c>true</c>, the key can only be used after the user authenticates with biometric or device credential.
    /// </summary>
    public bool RequireUserAuthentication { get; set; } = true;

    /// <summary>
    /// Block mode (CBC, GCM, etc). Default: GCM.
    /// <para>Only applicable to AES keys. RSA/EC keys should use <see cref="BlockMode.None"/>.</para>
    /// <para><b>Note:</b> GCM mode requires <see cref="Padding.None"/>.</para>
    /// </summary>
    public BlockMode BlockMode { get; set; } = BlockMode.Gcm;

    /// <summary>
    /// Padding scheme. Default: None (correct for AES-GCM).
    /// <para><b>Note:</b> GCM mode requires <see cref="Padding.None"/>.
    /// CBC mode requires a padding scheme (e.g., <see cref="Padding.Pkcs7"/>).</para>
    /// </summary>
   public Padding Padding { get; set; } = Padding.None;

    /// <summary>
    /// Digest algorithm (for signatures). Default: SHA256.
    /// Used when creating keys for Sign/Verify operations.
    /// </summary>
    public Digest Digest { get; set; } = Digest.Sha256;
}
