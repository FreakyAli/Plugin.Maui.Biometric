using System.Diagnostics.CodeAnalysis;

namespace Plugin.Maui.Biometric;

[Experimental("BIOCRYPTO001")]
internal sealed partial class SecureBiometricService : ISecureBiometric
{
    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token);

    [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token);

    // ─── Shared Validation (R3) ──────────────────────────────────────────────

    internal static SecureAuthenticationResponse? ValidateSignInput(string keyId, byte[] inputData)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return SecureAuthenticationResponse.Failure("KeyId cannot be null or empty.");

        if (inputData is null || inputData.Length == 0)
            return SecureAuthenticationResponse.Failure("Input data cannot be null or empty.");

        return null;
    }

    internal static SecureAuthenticationResponse? ValidateVerifyInput(string keyId, byte[] inputData, byte[] signature)
    {
        var signValidation = ValidateSignInput(keyId, inputData);
        if (signValidation is not null)
            return signValidation;

        if (signature is null || signature.Length == 0)
            return SecureAuthenticationResponse.Failure("Signature cannot be null or empty.");

        return null;
    }
}
