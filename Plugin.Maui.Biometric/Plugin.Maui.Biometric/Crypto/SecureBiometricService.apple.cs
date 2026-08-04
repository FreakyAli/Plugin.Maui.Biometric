namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        var validationResult = KeyCreationHelpers.PerformKeyCreationValidation(keyId, options);
        if (!validationResult.WasSuccessful)
            return Task.FromResult(validationResult);

        // AES/RSA are always Keychain-backed (software); requiring hardware fails for those.
        if (options.RequireHardwareBacking && options.Algorithm != KeyAlgorithm.Ec)
            return Task.FromResult(KeyOperationResult.Failure(
                $"Hardware backing is only available for EC keys on Apple platforms. {options.Algorithm} keys are stored in the Keychain (software-backed)."));

        // EC with RequireHardwareBacking needs Secure Enclave
        if (options.RequireHardwareBacking && options.Algorithm == KeyAlgorithm.Ec &&
            !AppleKeychainHelpers.IsSecureEnclaveAvailable())
            return Task.FromResult(KeyOperationResult.Failure(
                "Hardware-backed security is required but the Secure Enclave is not available on this device."));

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
        => request.Algorithm switch
        {
            KeyAlgorithm.Aes => LAContextCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: true, token),
            KeyAlgorithm.Rsa => LAContextCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: true, token),
            _ => Task.FromResult(SecureAuthenticationResponse.Failure(
                $"Encrypt is not supported for {request.Algorithm} keys. Use AES or RSA."))
        };

    public partial Task<SecureAuthenticationResponse> DecryptAsync(
        SecureAuthenticationRequest request, CancellationToken token)
        => request.Algorithm switch
        {
            KeyAlgorithm.Aes => LAContextCryptoHelpers.ProcessAesCryptoAsync(request, encrypt: false, token),
            KeyAlgorithm.Rsa => LAContextCryptoHelpers.ProcessRsaCryptoAsync(request, encrypt: false, token),
            _ => Task.FromResult(SecureAuthenticationResponse.Failure(
                $"Decrypt is not supported for {request.Algorithm} keys. Use AES or RSA."))
        };

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
