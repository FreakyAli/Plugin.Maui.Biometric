using System.Diagnostics.CodeAnalysis;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Provides hardware-backed cryptographic operations gated by biometric authentication.
/// <para>
/// <b>Platform capabilities and limitations:</b>
/// </para>
/// <para>
/// <b>Android (API 26+):</b>
/// <list type="bullet">
///   <item>Keys are stored in the Android KeyStore with StrongBox (API 28+) or TEE fallback.</item>
///   <item>AES keys are created via <c>KeyGenerator</c>; RSA/EC keys via <c>KeyPairGenerator</c>.</item>
///   <item>Encrypt/Decrypt operations are cryptographically bound to biometric auth via <c>BiometricPrompt.CryptoObject</c>
///     — the cipher <b>cannot</b> be used without completing biometric authentication.</item>
///   <item><b>StrongBox limitations:</b> Only supports AES 128/256, RSA 2048, and EC P-256.
///     Larger keys (RSA 3072/4096, EC P-384/P-521) fall back to TEE or software.
///     StrongBox is slower and supports fewer concurrent operations.
///     See: <see href="https://developer.android.com/privacy-and-security/keystore"/></item>
///   <item><b>Sign/Verify:</b> Not yet implemented — returns a failure response.</item>
///   <item><b>Per-operation auth:</b> On API 26–29, uses the deprecated
///     <c>SetUserAuthenticationValidityDurationSeconds(-1)</c>; on API 30+ per-operation auth is the default.</item>
/// </list>
/// </para>
/// <para>
/// <b>iOS / macOS:</b>
/// <list type="bullet">
///   <item>AES keys are stored as <c>GenericPassword</c> items in the Keychain (software-backed).</item>
///   <item>EC keys are stored in the <b>Secure Enclave</b> when available (A7+ / T1/T2 / Apple Silicon).
///     <b>The Secure Enclave only supports EC P-256 (secp256r1).</b>
///     EC P-384 and P-521 keys are NOT stored in the Secure Enclave — they remain in the Keychain.
///     See: <see href="https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave"/></item>
///   <item>RSA keys are stored in the Keychain with biometric access control (not Secure Enclave).</item>
///   <item>Biometric access uses <c>BiometryCurrentSet</c> — keys are invalidated if biometrics change
///     (e.g., a new fingerprint is enrolled). Keys use <c>WhenPasscodeSetThisDeviceOnly</c> so they
///     become unavailable if the device passcode is removed.</item>
///   <item><c>LAContext</c> objects consume Secure Enclave resources; avoid holding many key references
///     simultaneously. The plugin retrieves keys from the Keychain on demand and releases promptly.</item>
///   <item>Sign/Verify support EC and RSA with configurable <see cref="Digest"/> algorithms.</item>
/// </list>
/// </para>
/// <para>
/// <b>Windows:</b>
/// <list type="bullet">
///   <item>AES keys are stored in <c>PasswordVault</c> (DPAPI-encrypted, <b>software-backed, not TPM-bound</b>).
///     The biometric gate (<c>UserConsentVerifier</c>) and key access are <b>two separate, unlinked steps</b>.
///     Unlike Android/Apple, a process running as the same user could access the PasswordVault key
///     without biometric authentication.
///     See: <see href="https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello"/></item>
///   <item>RSA/EC keys are managed via <c>KeyCredentialManager</c> (Windows Hello), which is TPM-backed
///     where available (TPM 2.0), with software fallback on devices without a TPM.
///     Windows Hello keys are user+device scoped, not per-application.</item>
///   <item><b>RSA/EC encrypt/decrypt is not supported</b> on Windows — Windows Hello keys only support signing.
///     Use AES for encryption. <c>CreateKeyAsync</c> will reject RSA/EC keys that include Encrypt/Decrypt operations.</item>
///   <item><b>Windows Hello prompts do not support cancellation</b> — the <see cref="CancellationToken"/>
///     is checked between operations but cannot cancel a prompt that is already showing.</item>
///   <item>TPM 1.2 devices only support RSA; TPM 2.0 supports RSA + EC. Devices without TPM use software keys.</item>
/// </list>
/// </para>
/// </summary>
[Experimental("BIOCRYPTO001")]
public interface ISecureBiometric
{
    /// <summary>
    /// Create a hardware-backed key for future cryptographic operations.
    /// <para><b>Android:</b> AES via <c>KeyGenerator</c>, RSA/EC via <c>KeyPairGenerator</c>.
    /// StrongBox is attempted first (API 28+), falls back to TEE/Software.
    /// StrongBox only supports AES 128/256, RSA 2048, and EC P-256 — larger keys use TEE.</para>
    /// <para><b>iOS/macOS:</b> AES via <c>RandomNumberGenerator</c> + Keychain.
    /// EC P-256 keys go to the Secure Enclave; RSA and larger EC keys stay in the Keychain.</para>
    /// <para><b>Windows:</b> AES via <c>RandomNumberGenerator</c> + <c>PasswordVault</c> (DPAPI, not TPM).
    /// RSA/EC via <c>KeyCredentialManager</c> (TPM-backed where available).
    /// <b>Windows rejects RSA/EC keys with Encrypt|Decrypt operations</b> — only Sign|Verify is supported.</para>
    /// </summary>
    Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options);

    /// <summary>
    /// Delete a key from the keystore / Secure Enclave.
    /// Idempotent: returns success if the key was already deleted or never existed.
    /// </summary>
    Task<KeyOperationResult> DeleteKeyAsync(string keyId);

    /// <summary>
    /// Check if a key exists.
    /// </summary>
    Task<KeyOperationResult> KeyExistsAsync(string keyId);

    /// <summary>
    /// Encrypt input data using a hardware-backed key.
    /// <para><b>Android:</b> <c>Cipher</c> with <c>BiometricPrompt.CryptoObject</c>
    /// (cryptographically bound to biometric auth — the cipher cannot be used without authentication).</para>
    /// <para><b>iOS/macOS:</b> AES-GCM with biometric-protected Keychain key, or RSA public key
    /// (no biometric needed for RSA encrypt, biometric required for RSA decrypt).</para>
    /// <para><b>Windows:</b> AES-GCM only. Biometric prompt is shown but is <b>not</b>
    /// cryptographically bound to key access. RSA encrypt is not supported.</para>
    /// </summary>
    Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token);

    /// <summary>
    /// Decrypt input data using a hardware-backed key.
    /// <para><b>Android:</b> <c>Cipher</c> with <c>BiometricPrompt.CryptoObject</c>.</para>
    /// <para><b>iOS/macOS:</b> AES-GCM with biometric-protected Keychain key, or RSA private key (biometric required).</para>
    /// <para><b>Windows:</b> AES-GCM only. RSA decrypt is not supported on Windows.</para>
    /// </summary>
    Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token);

    /// <summary>
    /// Sign input data using a hardware-backed key.
    /// <para><b>Android:</b> Not yet implemented — returns a failure response.</para>
    /// <para><b>iOS/macOS:</b> Supports EC (ECDSA X9.62) and RSA (PKCS1v15) with configurable digest.
    /// Biometric authentication is required to access the private key.</para>
    /// <para><b>Windows:</b> Signs via Windows Hello <c>KeyCredential.RequestSignAsync</c>
    /// (biometric prompt triggered automatically by the OS).
    /// Note: Windows always uses RSA PKCS1 SHA256 regardless of the <paramref name="algorithm"/>
    /// and <paramref name="digest"/> parameters — these are determined by the Windows Hello key type.</para>
    /// </summary>
    /// <param name="keyId">The key alias used during <see cref="CreateKeyAsync"/>.</param>
    /// <param name="inputData">The raw data to sign.</param>
    /// <param name="algorithm">The key algorithm (EC or RSA). Must match the key created.
    /// Ignored on Windows (Windows Hello determines the algorithm).</param>
    /// <param name="digest">The digest algorithm to use (e.g. SHA256, SHA512).
    /// Ignored on Windows.</param>
    /// <param name="token">Cancellation token. Windows Hello prompts cannot be cancelled once shown.</param>
    Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token);

    /// <summary>
    /// Verify signature against input data using a hardware-backed key.
    /// No biometric authentication is required for verification (uses the public key).
    /// <para><b>Android:</b> Not yet implemented — returns a failure response.</para>
    /// <para><b>iOS/macOS:</b> Supports EC (ECDSA X9.62) and RSA (PKCS1v15) with configurable digest.
    /// No biometric required — verification uses the public key.</para>
    /// <para><b>Windows:</b> Verifies via the Windows Hello public key using RSA PKCS1 SHA256.
    /// The <paramref name="algorithm"/> and <paramref name="digest"/> parameters are ignored —
    /// Windows Hello keys always use the algorithm determined at key creation time.</para>
    /// </summary>
    /// <param name="keyId">The key alias used during <see cref="CreateKeyAsync"/>.</param>
    /// <param name="inputData">The original data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="algorithm">The key algorithm (EC or RSA). Must match the key created.
    /// Ignored on Windows.</param>
    /// <param name="digest">The digest algorithm that was used for signing.
    /// Ignored on Windows.</param>
    /// <param name="token">Cancellation token.</param>
    Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token);
}
