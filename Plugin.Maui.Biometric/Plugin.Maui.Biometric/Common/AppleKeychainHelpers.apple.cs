using Foundation;
using LocalAuthentication;
using Security;
using System.Security.Cryptography;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Static helper for Apple Keychain and Secure Enclave key management.
/// Mirrors <c>AndroidKeyStoreHelpers</c> on Android.
/// </summary>
internal static class AppleKeychainHelpers
{
    // AES keys are stored as GenericPassword items under this service name.
    // RSA/EC keys are stored as SecKind.Key items with ApplicationLabel = keyId.
    internal const string ServiceName = "Plugin.Maui.Biometric";

    // ─── Key Creation ────────────────────────────────────────────────────────

    /// <summary>
    /// Generate a random AES key and store it as a biometric-protected
    /// GenericPassword item in the Keychain.
    /// </summary>
    internal static KeyOperationResult CreateSymmetricKey(string keyId, CryptoKeyOptions options)
    {
        try
        {
            var keyBytes = RandomNumberGenerator.GetBytes(options.KeySize / 8);

            var sac = BuildAccessControl(options.RequireUserAuthentication);

            var record = new SecRecord(SecKind.GenericPassword)
            {
                Account = keyId,
                Service = ServiceName,
                Label = keyId,
                ValueData = NSData.FromArray(keyBytes),
                AccessControl = sac
            };

            return SecKeyChain.Add(record) switch
            {
                SecStatusCode.DuplicateItem => KeyOperationResult.Failure($"Key '{keyId}' already exists."),
                SecStatusCode.Success => KeyOperationResult.Success("Keychain", $"AES-{options.KeySize} key stored in Keychain."),
                var s => KeyOperationResult.Failure($"Failed to store key in Keychain: {s}")
            };
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Key creation error: {ex.GetFullMessage()}");
        }
    }

    /// <summary>
    /// Create an RSA or EC key pair.
    /// EC keys are placed in the Secure Enclave when available; RSA keys
    /// are placed in the Keychain with biometric access control.
    /// </summary>
    internal static KeyOperationResult CreateAsymmetricKey(string keyId, CryptoKeyOptions options)
    {
        try
        {
            bool useSecureEnclave = options.Algorithm == KeyAlgorithm.Ec && IsSecureEnclaveAvailable();

            // Secure Enclave requires PrivateKeyUsage flag; ordinary Keychain uses UserPresence.
            var acFlags = useSecureEnclave
                ? SecAccessControlCreateFlags.PrivateKeyUsage | SecAccessControlCreateFlags.BiometryCurrentSet
                : SecAccessControlCreateFlags.UserPresence;

            var sac = new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly, acFlags);

            // Private key attributes: permanent storage, labelled by keyId, protected by SAC.
            var privateKeyAttrs = new SecKeyParameters
            {
                IsPermanent = true,
                ApplicationTag = NSData.FromString(keyId),
                AccessControl = sac
            };

            var keyParams = new SecKeyGenerationParameters
            {
                KeyType = MapKeyType(options.Algorithm),
                KeySizeInBits = options.KeySize,
                PrivateKeyAttrs = privateKeyAttrs
            };

            if (useSecureEnclave)
                keyParams.TokenID = SecTokenID.SecureEnclave;

            using var key = SecKey.CreateRandomKey(keyParams, out NSError? keyError);
            if (key is null)
                return KeyOperationResult.Failure($"Failed to create key: {keyError?.GetErrorMessage()}");

            var level = useSecureEnclave ? "Secure Enclave" : "Keychain";
            return KeyOperationResult.Success(level, $"Key created in {level}.");
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Key creation error: {ex.GetFullMessage()}");
        }
    }

    // ─── Key Deletion ─────────────────────────────────────────────────────────

    /// <summary>
    /// Removes the key from the Keychain.  Tries both GenericPassword (AES)
    /// and Key (RSA/EC) storage classes, mirroring how Android's KeyStore
    /// handles all types under a single alias.
    /// </summary>
    internal static KeyOperationResult DeleteKey(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");

        try
        {
            var passwordStatus = SecKeyChain.Remove(new SecRecord(SecKind.GenericPassword)
            {
                Account = keyId,
                Service = ServiceName
            });

            var keyStatus = SecKeyChain.Remove(new SecRecord(SecKind.Key)
            {
                ApplicationLabel = keyId
            });

            bool bothAcceptable =
                (passwordStatus is SecStatusCode.Success or SecStatusCode.ItemNotFound) &&
                (keyStatus is SecStatusCode.Success or SecStatusCode.ItemNotFound);

            if (!bothAcceptable)
                return KeyOperationResult.Failure(
                    $"Failed to delete key (password={passwordStatus}, key={keyStatus}).");

            bool actuallyDeleted = passwordStatus == SecStatusCode.Success
                                || keyStatus == SecStatusCode.Success;

            return actuallyDeleted
                ? KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' successfully deleted.")
                : KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' was already deleted or never existed.");
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Delete error: {ex.GetFullMessage()}");
        }
    }

    // ─── Key Existence ────────────────────────────────────────────────────────

    internal static KeyOperationResult KeyExists(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");

        try
        {
            // Check AES (GenericPassword)
            SecKeyChain.QueryAsRecord(new SecRecord(SecKind.GenericPassword)
            {
                Account = keyId,
                Service = ServiceName
            }, out SecStatusCode passwordStatus);

            if (passwordStatus == SecStatusCode.Success)
                return KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' exists.");

            // Check RSA/EC (Key)
            SecKeyChain.QueryAsConcreteType(new SecRecord(SecKind.Key)
            {
                ApplicationLabel = keyId
            }, out SecStatusCode keyStatus);

            return keyStatus == SecStatusCode.Success
                ? KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' exists.")
                : KeyOperationResult.Failure($"Key '{keyId}' does not exist.");
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Key existence check error: {ex.GetFullMessage()}");
        }
    }

    // ─── Key Retrieval ────────────────────────────────────────────────────────

    /// <summary>
    /// Retrieve AES key bytes from the Keychain using an already-authenticated
    /// <see cref="LAContext"/> so no additional biometric prompt is shown.
    /// </summary>
    internal static (byte[]? keyBytes, string? error) RetrieveSymmetricKey(
        string keyId, LAContext authenticatedContext)
    {
        try
        {
            var record = new SecRecord(SecKind.GenericPassword)
            {
                Account = keyId,
                Service = ServiceName,
                AuthenticationContext = authenticatedContext
            };

            var result = SecKeyChain.QueryAsRecord(record, out SecStatusCode status);
            if (status != SecStatusCode.Success || result?.ValueData is null)
                return (null, $"Failed to retrieve AES key from Keychain: {status}");

            return (result.ValueData.ToArray(), null);
        }
        catch (Exception ex)
        {
            return (null, $"Key retrieval error: {ex.GetFullMessage()}");
        }
    }

    /// <summary>
    /// Retrieve the private half of an RSA/EC key using an already-authenticated
    /// <see cref="LAContext"/>.  Biometric UI will not be shown again.
    /// </summary>
    internal static (SecKey? privateKey, string? error) RetrieveAsymmetricPrivateKey(
        string keyId, LAContext authenticatedContext)
    {
        try
        {
            var record = new SecRecord(SecKind.Key)
            {
                ApplicationLabel = keyId,
                KeyClass = SecKeyClass.Private,
                AuthenticationContext = authenticatedContext
            };

            var key = SecKeyChain.QueryAsConcreteType(record, out SecStatusCode status) as SecKey;
            if (status != SecStatusCode.Success || key is null)
                return (null, $"Failed to retrieve private key: {status}");

            return (key, null);
        }
        catch (Exception ex)
        {
            return (null, $"Private key retrieval error: {ex.GetFullMessage()}");
        }
    }

    /// <summary>
    /// Retrieve the public half of an RSA/EC key.  No biometric required.
    /// </summary>
    internal static (SecKey? publicKey, string? error) RetrieveAsymmetricPublicKey(string keyId)
    {
        try
        {
            var record = new SecRecord(SecKind.Key)
            {
                ApplicationLabel = keyId,
                KeyClass = SecKeyClass.Public
            };

            var key = SecKeyChain.QueryAsConcreteType(record, out SecStatusCode status) as SecKey;
            if (status != SecStatusCode.Success || key is null)
                return (null, $"Failed to retrieve public key: {status}");

            return (key, null);
        }
        catch (Exception ex)
        {
            return (null, $"Public key retrieval error: {ex.GetFullMessage()}");
        }
    }

    // ─── Platform Checks ──────────────────────────────────────────────────────

    /// <summary>
    /// Returns <c>true</c> when the device has a Secure Enclave and biometrics enrolled
    /// (A7+ / T1/T2 chip / Apple Silicon).
    /// </summary>
    internal static bool IsSecureEnclaveAvailable()
    {
        try
        {
            using var context = new LAContext();
            return context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out _);
        }
        catch
        {
            return false;
        }
    }

    // ─── Access Control ───────────────────────────────────────────────────────

    private static SecAccessControl BuildAccessControl(bool requireBiometric)
    {
        var flags = requireBiometric
            ? SecAccessControlCreateFlags.BiometryCurrentSet
            : SecAccessControlCreateFlags.UserPresence;

        return new SecAccessControl(SecAccessible.WhenPasscodeSetThisDeviceOnly, flags);
    }

    // ─── Algorithm Mappings ───────────────────────────────────────────────────

    internal static SecKeyType MapKeyType(KeyAlgorithm algorithm) =>
        algorithm switch
        {
            KeyAlgorithm.Rsa => SecKeyType.RSA,
            KeyAlgorithm.Ec => SecKeyType.EC,
            _ => SecKeyType.EC
        };

    /// <summary>Maps the requested padding to the correct RSA encryption algorithm.</summary>
    internal static SecKeyAlgorithm MapEncryptAlgorithm(Padding padding) =>
        padding switch
        {
            Padding.Oaep => SecKeyAlgorithm.RsaEncryptionOaepSha256,
            _ => SecKeyAlgorithm.RsaEncryptionPkcs1
        };

    /// <summary>Maps algorithm + digest to the correct signing algorithm constant.</summary>
    internal static SecKeyAlgorithm MapSignatureAlgorithm(KeyAlgorithm algorithm, Digest digest) =>
        algorithm switch
        {
            KeyAlgorithm.Ec => digest switch
            {
                Digest.Sha1 => SecKeyAlgorithm.EcdsaSignatureMessageX962Sha1,
                Digest.Sha384 => SecKeyAlgorithm.EcdsaSignatureMessageX962Sha384,
                Digest.Sha512 => SecKeyAlgorithm.EcdsaSignatureMessageX962Sha512,
                _ => SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256
            },
            KeyAlgorithm.Rsa => digest switch
            {
                Digest.Sha1 => SecKeyAlgorithm.RsaSignatureMessagePkcs1v15Sha1,
                Digest.Sha384 => SecKeyAlgorithm.RsaSignatureMessagePkcs1v15Sha384,
                Digest.Sha512 => SecKeyAlgorithm.RsaSignatureMessagePkcs1v15Sha512,
                _ => SecKeyAlgorithm.RsaSignatureMessagePkcs1v15Sha256
            },
            _ => SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256
        };
}
