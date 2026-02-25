using System.Security.Cryptography;
using Windows.Security.Credentials;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Static helper for Windows key management using PasswordVault and Windows Hello.
/// Mirrors <c>AppleKeychainHelpers</c> on iOS/macOS and <c>AndroidKeyStoreHelpers</c> on Android.
/// </summary>
internal static class WindowsKeyVaultHelpers
{
    // AES keys are stored as PasswordVault credentials under this resource name.
    // RSA/EC keys are stored as Windows Hello KeyCredentials keyed by keyId.
    internal const string VaultResource = "Plugin.Maui.Biometric";

    private const string AesKeyPrefix = "aes:";

    // ─── Key Creation ─────────────────────────────────────────────────────────

    /// <summary>
    /// Generate a random AES key and store it as a PasswordVault credential.
    /// </summary>
    internal static KeyOperationResult CreateSymmetricKey(string keyId, CryptoKeyOptions options)
    {
        try
        {
            var keyBytes   = RandomNumberGenerator.GetBytes(options.KeySize / 8);
            var encodedKey = Convert.ToBase64String(keyBytes);

            var vault = new PasswordVault();
            vault.Add(new PasswordCredential(VaultResource, AesKeyPrefix + keyId, encodedKey));

            return KeyOperationResult.Success("PasswordVault", $"AES-{options.KeySize} key stored in PasswordVault.");
        }
        catch (Exception ex) when (ex.HResult == unchecked((int)0x80070057)) // item already exists
        {
            return KeyOperationResult.Failure($"Key '{keyId}' already exists.");
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Key creation error: {ex.GetFullMessage()}");
        }
    }

    /// <summary>
    /// Create a Windows Hello key pair via <see cref="KeyCredentialManager"/>.
    /// Both RSA and EC keys are stored as Windows Hello credentials (TPM-backed where available).
    /// </summary>
    internal static async Task<KeyOperationResult> CreateAsymmetricKeyAsync(string keyId, CryptoKeyOptions options)
    {
        try
        {
            var result = await KeyCredentialManager.RequestCreateAsync(
                keyId, KeyCredentialCreationOption.FailIfExists);

            return result.Status switch
            {
                KeyCredentialStatus.Success =>
                    KeyOperationResult.Success("Windows Hello", "Key created in Windows Hello."),
                KeyCredentialStatus.CredentialAlreadyExists =>
                    KeyOperationResult.Failure($"Key '{keyId}' already exists."),
                KeyCredentialStatus.UserCanceled =>
                    KeyOperationResult.Failure("Key creation was cancelled by user."),
                KeyCredentialStatus.NotFound =>
                    KeyOperationResult.Failure("Windows Hello is not set up on this device."),
                _ => KeyOperationResult.Failure($"Key creation failed: {result.Status}")
            };
        }
        catch (Exception ex)
        {
            return KeyOperationResult.Failure($"Key creation error: {ex.GetFullMessage()}");
        }
    }

    // ─── Key Deletion ──────────────────────────────────────────────────────────

    /// <summary>
    /// Removes the key from PasswordVault (AES) and Windows Hello (RSA/EC).
    /// Mirrors how Android's KeyStore and Apple's Keychain handle all types under a single alias.
    /// </summary>
    internal static async Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");

        bool deletedAes          = TryDeleteFromVault(AesKeyPrefix + keyId);
        bool deletedWindowsHello = await TryDeleteWindowsHelloKeyAsync(keyId);

        return (deletedAes || deletedWindowsHello)
            ? KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' successfully deleted.")
            : KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' was already deleted or never existed.");
    }

    // ─── Key Existence ────────────────────────────────────────────────────────

    internal static async Task<KeyOperationResult> KeyExistsAsync(string keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");

        try
        {
            // Check AES (PasswordVault)
            if (TryFindInVault(AesKeyPrefix + keyId))
                return KeyOperationResult.Success(additionalInfo: $"Key '{keyId}' exists.");

            // Check RSA/EC (Windows Hello)
            var result = await KeyCredentialManager.OpenAsync(keyId);
            return result.Status == KeyCredentialStatus.Success
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
    /// Retrieve AES key bytes from PasswordVault.
    /// The caller should gate this with <see cref="Windows.Security.Credentials.UI.UserConsentVerifier"/>
    /// before calling to enforce biometric protection.
    /// </summary>
    internal static (byte[]? keyBytes, string? error) RetrieveSymmetricKey(string keyId)
    {
        try
        {
            var vault      = new PasswordVault();
            var credential = vault.Retrieve(VaultResource, AesKeyPrefix + keyId);
            credential.RetrievePassword();

            return (Convert.FromBase64String(credential.Password), null);
        }
        catch (Exception ex)
        {
            return (null, $"Key retrieval error: {ex.GetFullMessage()}");
        }
    }

    /// <summary>
    /// Open the Windows Hello <see cref="KeyCredential"/> for the given key ID.
    /// Signing with the returned credential will trigger the Windows Hello biometric prompt.
    /// </summary>
    internal static async Task<(KeyCredential? credential, string? error)> OpenWindowsHelloKeyAsync(string keyId)
    {
        try
        {
            var result = await KeyCredentialManager.OpenAsync(keyId);
            return result.Status == KeyCredentialStatus.Success
                ? (result.Credential, null)
                : (null, $"Failed to open Windows Hello key: {result.Status}");
        }
        catch (Exception ex)
        {
            return (null, $"Key open error: {ex.GetFullMessage()}");
        }
    }

    // ─── Private Helpers ──────────────────────────────────────────────────────

    private static bool TryDeleteFromVault(string credentialName)
    {
        try
        {
            var vault      = new PasswordVault();
            var credential = vault.Retrieve(VaultResource, credentialName);
            vault.Remove(credential);
            return true;
        }
        catch { return false; }
    }

    private static async Task<bool> TryDeleteWindowsHelloKeyAsync(string keyId)
    {
        try
        {
            await KeyCredentialManager.DeleteAsync(keyId);
            return true;
        }
        catch { return false; }
    }

    private static bool TryFindInVault(string credentialName)
    {
        try
        {
            new PasswordVault().Retrieve(VaultResource, credentialName);
            return true;
        }
        catch { return false; }
    }
}
