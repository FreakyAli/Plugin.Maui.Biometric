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

            var keyAlgorithm = AndroidKeyStoreHelpers.MapKeyAlgorithm(options.Algorithm);
            var purpose = AndroidKeyStoreHelpers.MapPurpose(options.Operation);

            // Try StrongBox first, then fall back
            var result = AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: true);
            if (result.WasSuccessful)
            {
                return Task.FromResult(result);
            }

            // If StrongBox failed, try without StrongBox (TEE/Software)
            result = AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: false);
            return Task.FromResult(result);
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

    public partial async Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => await BiometricPromptHelpers.ProcessCryptoAsync(request, CipherMode.DecryptMode, token);

    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        return Task.FromResult(SecureAuthenticationResponse.Failure("Key not found or operation canceled."));
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        if (signature is null || signature.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Signature cannot be null or empty."));

        return Task.FromResult(SecureAuthenticationResponse.Failure("Key not found or operation canceled."));
    }
}