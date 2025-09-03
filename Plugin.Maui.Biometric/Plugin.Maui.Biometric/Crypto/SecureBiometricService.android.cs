using Java.Security;
using Javax.Crypto;

namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "KeyId cannot be null or empty."
            });
        }

        if (options is null)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "Options cannot be null."
            });
        }

        if (options.Operation == 0)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "At least one operation must be specified."
            });
        }

        // Validate algorithm/mode/padding combinations
        if (options.BlockMode == BlockMode.Gcm && options.Padding != Padding.None)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "GCM mode cannot be used with padding. Set Padding to None."
            });
        }

        if (options.Algorithm == KeyAlgorithm.Ec && (options.Operation.HasFlag(CryptoOperation.Encrypt) || options.Operation.HasFlag(CryptoOperation.Decrypt)))
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "EC keys cannot be used for encrypt/decrypt operations. Use RSA or AES instead."
            });
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to access Android KeyStore."
                });
            }

            keyStore.Load(null);

            if (keyStore.ContainsAlias(keyId))
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = $"Key with alias '{keyId}' already exists."
                });
            }

            var keyAlgorithm = AndroidKeyStoreHelpers.MapKeyAlgorithm(options.Algorithm);
            var purpose = AndroidKeyStoreHelpers.MapPurpose(options.Operation);

            // Try StrongBox first, then fall back
            var result = AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: true);
            if (result.Success)
            {
                return Task.FromResult(result);
            }

            // If StrongBox failed, try without StrongBox (TEE/Software)
            result = AndroidKeyStoreHelpers.TryCreateKeyWithSecurityLevel(keyId, keyAlgorithm, purpose, options, preferStrongBox: false);
            return Task.FromResult(result);
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"KeyStore error while checking key '{keyId}': {ex.Message}"
            });
        }
        catch (IOException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Storage I/O error: {ex.Message}"
            });
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Algorithm not supported: {ex.Message}"
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            });
        }
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "KeyId cannot be null or empty."
            });
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to access Android KeyStore."
                });
            }

            keyStore.Load(null);

            if (!keyStore.ContainsAlias(keyId))
            {
                // Successful no-op - key already doesn't exist
                return Task.FromResult(new KeyOperationResult
                {
                    Success = true,
                    AdditionalInfo = $"Key '{keyId}' was already deleted or never existed."
                });
            }

            keyStore.DeleteEntry(keyId);

            return Task.FromResult(new KeyOperationResult
            {
                Success = true,
                AdditionalInfo = $"Key '{keyId}' successfully deleted."
            });
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"KeyStore error while checking key '{keyId}': {ex.Message}"
            });
        }
        catch (IOException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Storage I/O error: {ex.Message}"
            });
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Algorithm not supported: {ex.Message}"
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            });
        }
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "KeyId cannot be null or empty."
            });
        }

        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName);
            if (keyStore == null)
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to access Android KeyStore."
                });
            }

            keyStore.Load(null);

            var exists = keyStore.ContainsAlias(keyId);
            return Task.FromResult(new KeyOperationResult
            {
                Success = exists,
                AdditionalInfo = exists ? $"Key '{keyId}' exists." : $"Key '{keyId}' does not exist."
            });
        }
        catch (KeyStoreException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"KeyStore error while checking key '{keyId}': {ex.Message}"
            });
        }
        catch (IOException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Storage I/O error: {ex.Message}"
            });
        }
        catch (NoSuchAlgorithmException ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Algorithm not supported: {ex.Message}"
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            });
        }
    }

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => BiometricPromptHelpers.ProcessCryptoAsync(request, CipherMode.EncryptMode, token);

    public partial async Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => await BiometricPromptHelpers.ProcessCryptoAsync(request, CipherMode.DecryptMode, token);

    public partial Task<SecureAuthenticationResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        return Task.FromResult(SecureAuthenticationResponse.Failure("Key not found or operation canceled."));
    }

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