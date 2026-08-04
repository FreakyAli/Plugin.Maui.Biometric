namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        var validationResult = KeyCreationHelpers.PerformKeyCreationValidation(keyId, options);
        if (!validationResult.WasSuccessful)
            return Task.FromResult(validationResult);

        // Windows Hello keys support signing only — reject RSA/EC keys that request Encrypt/Decrypt.
        if (options.Algorithm != KeyAlgorithm.Aes &&
            (options.Operation.HasFlag(CryptoOperation.Encrypt) || options.Operation.HasFlag(CryptoOperation.Decrypt)))
        {
            return Task.FromResult(KeyOperationResult.Failure(
                $"{options.Algorithm} keys on Windows support signing only — Encrypt/Decrypt is not available. " +
                "Use AES for encryption or create RSA/EC keys with Sign|Verify operations only."));
        }

        try
        {
            return options.Algorithm == KeyAlgorithm.Aes
                ? Task.FromResult(WindowsKeyVaultHelpers.CreateSymmetricKey(keyId, options))
                : WindowsKeyVaultHelpers.CreateAsymmetricKeyAsync(keyId, options);
        }
        catch (Exception ex)
        {
            return Task.FromResult(KeyOperationResult.Failure(
                $"Key creation error: {ex.GetFullMessage()}"));
        }
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
        => WindowsKeyVaultHelpers.DeleteKeyAsync(keyId);

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
        => WindowsKeyVaultHelpers.KeyExistsAsync(keyId);

    public partial Task<SecureAuthenticationResponse> EncryptAsync(
        SecureAuthenticationRequest request, CancellationToken token)
        => request.Algorithm == KeyAlgorithm.Aes
            ? WindowsHelloCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: true, token)
            : WindowsHelloCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: true, token);

    public partial Task<SecureAuthenticationResponse> DecryptAsync(
        SecureAuthenticationRequest request, CancellationToken token)
        => request.Algorithm == KeyAlgorithm.Aes
            ? WindowsHelloCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: false, token)
            : WindowsHelloCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: false, token);

    public partial Task<SecureAuthenticationResponse> SignAsync(
        string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateSignInput(keyId, inputData);
        if (validation is not null)
            return Task.FromResult(validation);

        return WindowsHelloCryptoHelpers.ProcessSignAsync(keyId, inputData, token);
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(
        string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateVerifyInput(keyId, inputData, signature);
        if (validation is not null)
            return Task.FromResult(validation);

        return WindowsHelloCryptoHelpers.ProcessVerifyAsync(keyId, inputData, signature, token);
    }
}
