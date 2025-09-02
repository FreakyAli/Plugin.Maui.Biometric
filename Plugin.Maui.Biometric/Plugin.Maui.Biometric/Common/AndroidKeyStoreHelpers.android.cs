using AndroidX.Core.Content;
using Java.Security;
using Java.Util.Concurrent;
using Javax.Crypto;
using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;
using BiometricManager = AndroidX.Biometric.BiometricManager;
using Android.Security.Keystore;

namespace Plugin.Maui.Biometric;

internal class AndroidKeyStoreHelpers
{
    internal static readonly string KeyStoreName = "AndroidKeyStore";

    internal static async Task<SecureAuthenticationResponse> ProcessCryptoAsync(SecureAuthenticationRequest request, CipherMode mode, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(request.KeyId))
            return SecureAuthenticationResponse.Failure("Key ID cannot be null or empty");

        if (string.IsNullOrWhiteSpace(request.Transformation))
            return SecureAuthenticationResponse.Failure("Transformation cannot be null or empty");

        if (request.InputData == null || request.InputData.Length == 0)
            return SecureAuthenticationResponse.Failure("Input data cannot be null or empty");

        try
        {
            using var keyStore = KeyStore.GetInstance(KeyStoreName);
            if (keyStore == null)
                return SecureAuthenticationResponse.Failure("Failed to access Android KeyStore.");

            keyStore.Load(null);
            if (!keyStore.ContainsAlias(request.KeyId))
                return SecureAuthenticationResponse.Failure($"Key with alias '{request.KeyId}' does not exist.");

            using var key = keyStore.GetKey(request.KeyId, null);
            if (key == null)
                return SecureAuthenticationResponse.Failure($"Key '{request.KeyId}' could not be retrieved from KeyStore");

            using var cipher = Cipher.GetInstance(request.Transformation);
            if (cipher == null)
                return SecureAuthenticationResponse.Failure("Failed to create cipher.");
            cipher.Init(mode, key);

            if (Platform.CurrentActivity is not Activity activity)
                return SecureAuthenticationResponse.Failure(BiometricPromptHelpers.ActivityErrorMsg);

            var activityExecutor = ContextCompat.GetMainExecutor(activity);
            if (activityExecutor is not IExecutor executor)
                return SecureAuthenticationResponse.Failure(BiometricPromptHelpers.ExecutorErrorMsg);

            var strength = request.AuthStrength.Equals(AuthenticatorStrength.Strong)
                ? BiometricManager.Authenticators.BiometricStrong
                : BiometricManager.Authenticators.BiometricWeak;

            var allInfo = new BiometricPrompt.PromptInfo.Builder()
                .SetTitle(request.Title)
                .SetSubtitle(request.Subtitle)
                .SetDescription(request.Description);

            if (request.AllowPasswordAuth)
            {
                allInfo.SetAllowedAuthenticators(strength | BiometricManager.Authenticators.DeviceCredential);
            }
            else
            {
                allInfo.SetNegativeButtonText(request.NegativeText);
                allInfo.SetAllowedAuthenticators(strength);
            }

            var promptInfo = allInfo.Build();
            var authCallback = new SecureAuthCallback()
            {
                Request = request,
                Response = new TaskCompletionSource<SecureAuthenticationResponse>()
            };

            using var biometricPrompt = new BiometricPrompt(activity, executor, authCallback);
            using var cryptoObject = new BiometricPrompt.CryptoObject(cipher);
            using (token.Register(() => biometricPrompt.CancelAuthentication()))
            {
                biometricPrompt.Authenticate(promptInfo, cryptoObject);
                var response = await authCallback.Response.Task;
                return response;
            }
        }
        catch (UnrecoverableKeyException)
        {
            return SecureAuthenticationResponse.Failure("Key requires authentication but is not accessible");
        }
        catch (InvalidKeyException ex)
        {
            return SecureAuthenticationResponse.Failure($"Key '{request.KeyId}' is invalid for transformation '{request.Transformation}': {ex.Message}");
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"{mode} failed: {ex.Message}");
        }
    }

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
#pragma warning disable CA1422
                    keyGenSpecBuilder.SetUserAuthenticationValidityDurationSeconds(-1);
#pragma warning restore CA1422
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
                        (int)KeyStoreSecurityLevel.Strongbox => "StrongBox",
                        (int)KeyStoreSecurityLevel.TrustedEnvironment => "TEE",
                        (int)KeyStoreSecurityLevel.Software => "Software",
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
