using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;

namespace Plugin.Maui.Biometric;

internal class AndroidKeyStoreHelpers
{
    internal static readonly string KeyStoreName = "AndroidKeyStore";

    internal static KeyOperationResult TryCreateKeyWithSecurityLevel
                    (string keyId, string keyAlgorithm, KeyStorePurpose purpose,
                    CryptoKeyOptions options, bool preferStrongBox)
    {
        try
        {
            using var keyGen = KeyGenerator.GetInstance(keyAlgorithm, KeyStoreName);
            if (keyGen == null)
            {
                return new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = $"Failed to create key generator for algorithm {keyAlgorithm}."
                };
            }

            var keyGenSpecBuilder = new KeyGenParameterSpec.Builder(keyId, purpose)
                .SetKeySize(options.KeySize)
                .SetUserAuthenticationRequired(options.RequireUserAuthentication);

            // Biometric-specific configuration  
            if (options.RequireUserAuthentication)
            {
                // Per-operation auth this will accept BOTH biometric AND device credential 
                // (PIN/password/pattern)                                                
                // There's no way to restrict to biometric-only in the KeyStore on API 26-29
                if (Android.OS.Build.VERSION.SdkInt <= Android.OS.BuildVersionCodes.Q)
                {
                    keyGenSpecBuilder.SetUserAuthenticationValidityDurationSeconds(-1);
                }
            }

            // Algorithm-specific configuration
            if (options.Algorithm == KeyAlgorithm.Aes)
            {
                keyGenSpecBuilder
                    .SetBlockModes(MapBlockMode(options.BlockMode))
                    .SetEncryptionPaddings(MapPadding(options.Padding));
            }
            else if (options.Algorithm == KeyAlgorithm.Rsa)
            {
                keyGenSpecBuilder
                    .SetEncryptionPaddings(MapPadding(options.Padding))
                    .SetDigests(MapDigest(options.Digest));
            }
            else if (options.Algorithm == KeyAlgorithm.Ec)
            {
                keyGenSpecBuilder.SetDigests(MapDigest(options.Digest));
            }

            // Try StrongBox if requested and supported (Android 9+)
            if (preferStrongBox && OperatingSystem.IsAndroidVersionAtLeast(29))
            {
                keyGenSpecBuilder.SetIsStrongBoxBacked(true);
            }

            var keyGenSpec = keyGenSpecBuilder.Build();
            keyGen.Init(keyGenSpec);

            var secretKey = keyGen.GenerateKey();

            // Determine actual security level achieved
            var securityLevelName = GetActualSecurityLevel(keyId, preferStrongBox);

            var securityMessage = preferStrongBox
                ? $"Key created with {securityLevelName} security (StrongBox {(securityLevelName == "StrongBox" ? "achieved" : "fell back")})"
                : $"Key created with {securityLevelName} security";

            return new KeyOperationResult
            {
                Success = true,
                SecurityLevelName = securityLevelName, // Store string description
                AdditionalInfo = securityMessage
            };
        }
        catch (ProviderException ex) when (ex.Message?.Contains("StrongBox") == true)
        {
            if (preferStrongBox)
            {
                // StrongBox failed, caller should retry without it
                return new KeyOperationResult
                {
                    Success = false,
                    ErrorMessage = $"StrongBox unavailable: {ex.Message}",
                    ShouldRetry = true
                };
            }
            return new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Key creation failed: {ex.Message}"
            };
        }
        catch (InvalidAlgorithmParameterException ex)
        {
            return new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Invalid parameters for '{keyAlgorithm}': {ex.Message}"
            };
        }
        catch (KeyStoreException ex)
        {
            return new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"KeyStore error while checking key '{keyId}': {ex.Message}"
            };
        }
        catch (Exception ex)
        {
            return new KeyOperationResult
            {
                Success = false,
                ErrorMessage = $"Unexpected error: {ex.Message}"
            };
        }
    }

    internal static string GetVersionBasedSecurityLevel(IKey? key, bool strongBoxAttempted)
    {
        if (key is ISecretKey secretKey)
        {
            var keyFactory = SecretKeyFactory.GetInstance(secretKey.Algorithm, KeyStoreName);
            var keySpec = keyFactory?.GetKeySpec(secretKey, Java.Lang.Class.FromType(typeof(KeyInfo)));
            if (keySpec is KeyInfo keyInfo)
            {
                if (OperatingSystem.IsAndroidVersionAtLeast(31))
                {
                    return keyInfo.SecurityLevel switch
                    {
                        2 => "StrongBox",
                        1 => "TEE",
                        0 => "Software",
                        _ => "Software"
                    };
                }
                else
                {
                    var isHardwareBacked = keyInfo.IsInsideSecureHardware;
                    if (strongBoxAttempted && isHardwareBacked)
                        return "Hardware-backed (likely StrongBox)";
                    else if (isHardwareBacked)
                        return "Hardware-backed (TEE/StrongBox)";
                    else
                        return "Software";
                }
            }
        }
        return "Unknown";
    }

    internal static string GetActualSecurityLevel(string keyId, bool strongBoxAttempted)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(KeyStoreName);
            keyStore?.Load(null);
            var key = keyStore?.GetKey(keyId, null);
            return GetVersionBasedSecurityLevel(key, strongBoxAttempted);
        }
        catch
        {
            return "Unknown";
        }
    }

    internal static string MapKeyAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.Aes => KeyProperties.KeyAlgorithmAes,
            KeyAlgorithm.Rsa => KeyProperties.KeyAlgorithmRsa,
            KeyAlgorithm.Ec => KeyProperties.KeyAlgorithmEc,
            _ => KeyProperties.KeyAlgorithmAes // Default to AES
        };
    }

    internal static string MapTransformation(string keyAlgorithm, string blockMode, string encryptionPadding)
    {
        return $"{keyAlgorithm}/{blockMode}/{encryptionPadding}";
    }

    internal static KeyStorePurpose MapPurpose(CryptoOperation operation)
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

    internal static string MapBlockMode(BlockMode blockMode) =>
        blockMode switch
        {
            BlockMode.Cbc => KeyProperties.BlockModeCbc,
            BlockMode.Gcm => KeyProperties.BlockModeGcm,
            BlockMode.Ctr => KeyProperties.BlockModeCtr,
            BlockMode.Ecb => KeyProperties.BlockModeEcb,
            _ => KeyProperties.BlockModeGcm // Default
        };

    internal static string MapPadding(Padding padding) =>
        padding switch
        {
            Padding.None => KeyProperties.EncryptionPaddingNone,
            Padding.Pkcs7 => KeyProperties.EncryptionPaddingPkcs7,
            Padding.Pkcs1 => KeyProperties.EncryptionPaddingRsaPkcs1,
            Padding.Oaep => KeyProperties.EncryptionPaddingRsaOaep,
            _ => KeyProperties.EncryptionPaddingNone
        };

    internal static string MapDigest(Digest digest) =>
        digest switch
        {
            Digest.Sha1 => KeyProperties.DigestSha1,
            Digest.Sha224 => KeyProperties.DigestSha224,
            Digest.Sha256 => KeyProperties.DigestSha256,
            Digest.Sha384 => KeyProperties.DigestSha384,
            Digest.Sha512 => KeyProperties.DigestSha512,
            _ => KeyProperties.DigestSha256 // default
        };
}
