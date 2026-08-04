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
            var result = options.Algorithm == KeyAlgorithm.Aes
                ? AppleKeychainHelpers.CreateSymmetricKey(keyId, options)
                : AppleKeychainHelpers.CreateAsymmetricKey(keyId, options);

            return Task.FromResult(result);
        }
        catch (Exception ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Key creation error: {ex.GetFullMessage()}"));
        }
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
        => Task.FromResult(AppleKeychainHelpers.DeleteKey(keyId));

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
        => Task.FromResult(AppleKeychainHelpers.KeyExists(keyId));

    public partial Task<SecureAuthenticationResponse> EncryptAsync(
        SecureAuthenticationRequest request, CancellationToken token)
        => request.Algorithm == KeyAlgorithm.Aes
            ? LAContextCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: true, token)
            : LAContextCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: true, token);

    public partial Task<SecureAuthenticationResponse> DecryptAsync(
        SecureAuthenticationRequest request, CancellationToken token)
        => request.Algorithm == KeyAlgorithm.Aes
            ? LAContextCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: false, token)
            : LAContextCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: false, token);

    public partial Task<SecureAuthenticationResponse> SignAsync(
        string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateSignInput(keyId, inputData);
        if (validation is not null)
            return Task.FromResult(validation);

        return LAContextCryptoHelpers.ProcessSignAsync(
            keyId, inputData,
            algorithm:             algorithm,
            digest:                digest,
            localizedReason:       "Authenticate to sign data",
            allowPasswordFallback: false,
            token);
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(
        string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateVerifyInput(keyId, inputData, signature);
        if (validation is not null)
            return Task.FromResult(validation);

        return LAContextCryptoHelpers.ProcessVerifyAsync(
            keyId, inputData, signature,
            algorithm: algorithm,
            digest:    digest);
    }
}
