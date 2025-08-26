using System.Reflection;
using Android.Security.Keystore;
using AndroidX.Biometric;
using Java.Security;
using Javax.Crypto;

namespace Plugin.Maui.Biometric;

internal partial class BiometricCryptoService
{
    internal static readonly string KeyStoreName = "AndroidKeyStore";

    private static string MapKeyAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.Aes => KeyProperties.KeyAlgorithmAes,
            KeyAlgorithm.Rsa => KeyProperties.KeyAlgorithmRsa,
            KeyAlgorithm.Ec => KeyProperties.KeyAlgorithmEc,
            _ => KeyProperties.KeyAlgorithmAes // Default to AES
        };
    }

    private static string MapTransformation(string keyAlgorithm, string blockMode, string encryptionPadding)
    {
        return $"{keyAlgorithm}/{blockMode}/{encryptionPadding}";
    }

    private static KeyStorePurpose MapPurpose(CryptoOperation operation)
    {
        KeyStorePurpose purpose = 0;

        if (operation.HasFlag(CryptoOperation.Encrypt))
            purpose |= KeyStorePurpose.Encrypt;

        if (operation.HasFlag(CryptoOperation.Decrypt))
            purpose |= KeyStorePurpose.Decrypt;

        if (operation.HasFlag(CryptoOperation.Sign))
            purpose |= KeyStorePurpose.Sign;

        if (operation.HasFlag(CryptoOperation.Verify))
            purpose |= KeyStorePurpose.Verify;

        return purpose;
    }

    private static string MapBlockMode(BlockMode blockMode) =>
        blockMode switch
        {
            BlockMode.Cbc => KeyProperties.BlockModeCbc,
            BlockMode.Gcm => KeyProperties.BlockModeGcm,
            BlockMode.Ctr => KeyProperties.BlockModeCtr,
            BlockMode.Ecb => KeyProperties.BlockModeEcb,
            _ => KeyProperties.BlockModeCbc // Default
        };

    private static string MapPadding(Padding padding) =>
        padding switch
        {
            Padding.Pkcs7 => KeyProperties.EncryptionPaddingPkcs7,
            Padding.Pkcs1 => KeyProperties.EncryptionPaddingRsaPkcs1,
            Padding.Oaep => KeyProperties.EncryptionPaddingRsaOaep,
            _ => KeyProperties.EncryptionPaddingPkcs7
        };

    private static string MapDigest(Digest digest) =>
        digest switch
        {
            Digest.Sha1 => KeyProperties.DigestSha1,
            Digest.Sha224 => KeyProperties.DigestSha224,
            Digest.Sha256 => KeyProperties.DigestSha256,
            Digest.Sha384 => KeyProperties.DigestSha384,
            Digest.Sha512 => KeyProperties.DigestSha512,
            _ => KeyProperties.DigestSha256 // default
        };

    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        if (options.Operation == 0)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "Operation must be specified."
            });
        }

        // Check if key already exists
        using var keyStore = KeyStore.GetInstance(KeyStoreName);
        if (keyStore is null)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "Failed to create key generator"
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

        var keyAlgorithm = MapKeyAlgorithm(options.Algorithm);
        var purpose = MapPurpose(options.Operation);

        var keyGen = KeyGenerator.GetInstance(keyAlgorithm, KeyStoreName);
        if (keyGen is null)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = "Failed to create key generator"
            });
        }
        var keyGenSpecBuilder = new KeyGenParameterSpec.Builder(keyId, purpose)
            .SetBlockModes(MapBlockMode(options.BlockMode))
            .SetEncryptionPaddings(MapPadding(options.Padding))
            .SetKeySize(options.KeySize)
            .SetUserAuthenticationRequired(options.RequireUserAuthentication)
            .SetInvalidatedByBiometricEnrollment(true);

        // Apply digest if relevant (mainly for RSA/EC signing)
        if (options.Digest != Digest.None)
        {
            keyGenSpecBuilder.SetDigests(MapDigest(options.Digest));
        }

        var keyGenSpec = keyGenSpecBuilder.Build();
        keyGen.Init(keyGenSpec);

        try
        {
            var result = keyGen.GenerateKey();
            return Task.FromResult(new KeyOperationResult
            {
                Success = true
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = ex.Message + Environment.NewLine + ex.StackTrace
            });
        }
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(KeyStoreName);
            if (keyStore is null)
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = "Failed to create key generator"
                });
            }
            keyStore.Load(null);

            if (!keyStore.ContainsAlias(keyId))
            {
                return Task.FromResult(new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = $"Key with alias '{keyId}' does not exist."
                });
            }

            keyStore.DeleteEntry(keyId);

            return Task.FromResult(new KeyOperationResult
            {
                Success = true
            });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new KeyOperationResult
            {
                Success = false,
                ErrorMessage = ex.Message + Environment.NewLine + ex.StackTrace
            });
        }
    }

    public partial Task<bool> KeyExistsAsync(string keyId)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(KeyStoreName);
            if (keyStore is null)
            {
                return Task.FromResult(false);
            }
            keyStore.Load(null);

            return Task.FromResult(keyStore.ContainsAlias(keyId));
        }
        catch
        {
            return Task.FromResult(false);
        }
    }


    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureCryptoResponse.Failed("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Input data cannot be null or empty."));

        

        return Task.FromResult(SecureCryptoResponse.Failed("Key not found or operation canceled."));
    }

    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureCryptoResponse.Failed("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Input data cannot be null or empty."));

        
        return Task.FromResult(SecureCryptoResponse.Failed("Key not found or operation canceled."));
    }

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureCryptoResponse.Failed("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Input data cannot be null or empty."));

        return Task.FromResult(SecureCryptoResponse.Failed("Key not found or operation canceled."));
    }

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureCryptoResponse.Failed("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Input data cannot be null or empty."));

        return Task.FromResult(SecureCryptoResponse.Failed("Key not found or operation canceled."));
    }

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureCryptoResponse.Failed("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Input data cannot be null or empty."));

        if (signature is null || signature.Length == 0)
            return Task.FromResult(SecureCryptoResponse.Failed("Signature cannot be null or empty."));

        return Task.FromResult(SecureCryptoResponse.Failed("Key not found or operation canceled."));
    }
}