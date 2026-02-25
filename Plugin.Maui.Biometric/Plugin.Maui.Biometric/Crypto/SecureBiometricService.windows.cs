namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        var validationResult = KeyCreationHelpers.PerformKeyCreationValidation(keyId, options);
        if (!validationResult.WasSuccessful)
            return Task.FromResult(validationResult);

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
        string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        return WindowsHelloCryptoHelpers.ProcessSignAsync(keyId, inputData, token);
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(
        string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        if (signature is null || signature.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Signature cannot be null or empty."));

        return WindowsHelloCryptoHelpers.ProcessVerifyAsync(keyId, inputData, signature, token);
    }
}
