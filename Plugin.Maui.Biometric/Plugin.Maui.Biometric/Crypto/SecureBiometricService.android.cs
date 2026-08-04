using Java.Security;
using Javax.Crypto;

namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        var validationResult = KeyCreationHelpers.PerformKeyCreationValidation(keyId, options);
        if (!validationResult.WasSuccessful)
        {
            return Task.FromResult(validationResult);
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(KeyOperationResult.Failure("Failed to access Android KeyStore."));
            }

            keyStore.Load(null);

            if (keyStore.ContainsAlias(keyId))
            {
                return Task.FromResult(KeyOperationResult.Failure($"Key with alias '{keyId}' already exists."));
            }

            // Route symmetric (AES) and asymmetric (RSA/EC) to the appropriate generator
            return options.Algorithm == KeyAlgorithm.Aes
                ? Task.FromResult(CreateSymmetricKey(keyId, options))
                : Task.FromResult(CreateAsymmetricKey(keyId, options));
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"KeyStore error while checking key '{keyId}': {ex.GetFullMessage()}"));
        }
        catch (IOException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Storage I/O error: {ex.GetFullMessage()}"));
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Algorithm not supported: {ex.GetFullMessage()}"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Unexpected error: {ex.GetFullMessage()}"));
        }
    }

    /// <summary>
    /// Creates a symmetric AES key using <see cref="KeyGenerator"/>.
    /// </summary>
    private static KeyOperationResult CreateSymmetricKey(string keyId, CryptoKeyOptions options)
    {
        var keyAlgorithm = AndroidKeyStoreHelpers.MapKeyAlgorithm(options.Algorithm);
        var purpose = AndroidKeyStoreHelpers.MapPurpose(options.Operation);

        // Try StrongBox first, then fall back
        var result = AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: true);
        if (result.WasSuccessful)
            return result;

        // If StrongBox failed, try without StrongBox (TEE/Software)
        return AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: false);
    }

    /// <summary>
    /// Creates an asymmetric RSA or EC key pair using <see cref="KeyPairGenerator"/>.
    /// </summary>
    private static KeyOperationResult CreateAsymmetricKey(string keyId, CryptoKeyOptions options)
    {
        var keyAlgorithm = AndroidKeyStoreHelpers.MapKeyAlgorithm(options.Algorithm);
        var purpose = AndroidKeyStoreHelpers.MapPurpose(options.Operation);

        // Try StrongBox first, then fall back
        var result = AndroidKeyStoreHelpers.TryCreateKeyPairWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: true);
        if (result.WasSuccessful)
            return result;

        // If StrongBox failed, try without StrongBox (TEE/Software)
        return AndroidKeyStoreHelpers.TryCreateKeyPairWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: false);
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"KeyId cannot be null or empty."));
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(KeyOperationResult.Failure
                ($"Failed to access Android KeyStore."));
            }

            keyStore.Load(null);

            if (!keyStore.ContainsAlias(keyId))
            {
                // Successful no-op - key already doesn't exist
                return Task.FromResult(KeyOperationResult.Success
                (additionalInfo: $"Key '{keyId}' was already deleted or never existed."));
            }

            keyStore.DeleteEntry(keyId);

            return Task.FromResult(KeyOperationResult.Success
            (additionalInfo: $"Key '{keyId}' successfully deleted."));
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"KeyStore error while checking key '{keyId}': {ex.GetFullMessage()}"));
        }
        catch (IOException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Storage I/O error: {ex.GetFullMessage()}"));
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Algorithm not supported: {ex.GetFullMessage()}"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Unexpected error: {ex.GetFullMessage()}"));
        }
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"KeyId cannot be null or empty."));
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(KeyOperationResult.Failure
                ($"Failed to access Android KeyStore."));
            }

            keyStore.Load(null);

            var exists = keyStore.ContainsAlias(keyId);
            if (exists)
            {
                return Task.FromResult(KeyOperationResult.Success
                (additionalInfo: $"Key '{keyId}' exists."));
            }
            else
            {
                return Task.FromResult(KeyOperationResult.Failure
                ($"Key '{keyId}' does not exist."));
            }
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"KeyStore error while checking key '{keyId}': {ex.GetFullMessage()}"));
        }
        catch (Java.IO.IOException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Storage I/O error: {ex.GetFullMessage()}"));
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Algorithm not supported: {ex.GetFullMessage()}"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(KeyOperationResult.Failure
            ($"Unexpected error: {ex.GetFullMessage()}"));
        }
    }

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => BiometricPromptHelpers.ProcessCryptoAsync(request, CipherMode.EncryptMode, token);

    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => BiometricPromptHelpers.ProcessCryptoAsync(request, CipherMode.DecryptMode, token);

    /// <summary>
    /// Sign is not yet implemented on Android. Returns a failure response.
    /// </summary>
    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateSignInput(keyId, inputData);
        if (validation is not null)
            return Task.FromResult(validation);

        return Task.FromResult(SecureAuthenticationResponse.Failure(
            "Signing is not yet supported on Android. This feature will be added in a future release."));
    }

    /// <summary>
    /// Verify is not yet implemented on Android. Returns a failure response.
    /// </summary>
    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        var validation = ValidateVerifyInput(keyId, inputData, signature);
        if (validation is not null)
            return Task.FromResult(validation);

        return Task.FromResult(SecureAuthenticationResponse.Failure(
            "Verification is not yet supported on Android. This feature will be added in a future release."));
    }
}
