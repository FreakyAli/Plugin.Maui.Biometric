namespace Plugin.Maui.Biometric;

public class KeyCreationHelpers
{
    public static KeyOperationResult PerformKeyCreationValidation(string keyId, CryptoKeyOptions options)
    {
        var failure = GetValidationFailure(keyId, options);
        return failure ?? KeyOperationResult.Success();
    }

    // Returns null if all validations pass, or a Failure result if any rule fails.
    private static KeyOperationResult GetValidationFailure(string keyId, CryptoKeyOptions options)
    {
        if (IsKeyIdInvalid(keyId))
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");
        if (IsOptionsNull(options))
            return KeyOperationResult.Failure("Options cannot be null.");
        if (IsOperationInvalid(options))
            return KeyOperationResult.Failure("At least one operation must be specified.");
        if (IsBlockModePaddingInvalid(options))
            return KeyOperationResult.Failure("GCM mode cannot be used with padding. Set Padding to None.");
        if (IsEcEncryptDecryptInvalid(options))
            return KeyOperationResult.Failure("EC keys cannot be used for encrypt/decrypt operations. Use RSA or AES instead.");
        if (IsAesSignVerifyInvalid(options))
            return KeyOperationResult.Failure("AES keys cannot be used for sign/verify operations. Use RSA or EC instead.");
        if (IsAesBlockPaddingInvalid(options))
            return KeyOperationResult.Failure("AES keys require a valid BlockMode and Padding.");
        if (IsRsaOaepBlockModeInvalid(options))
            return KeyOperationResult.Failure("RSA with OAEP padding cannot be used with a BlockMode. Set BlockMode to None.");
        if (IsKeySizeInvalid(options))
            return KeyOperationResult.Failure("Key size must be between 128 and 8192 bits.");
        if (IsRsaKeySizeInvalid(options))
            return KeyOperationResult.Failure("RSA key size must be at least 2048 bits.");
        if (IsEcKeySizeInvalid(options))
            return KeyOperationResult.Failure("EC key size must be at least 256 bits.");
        return null;
    }

    private static bool IsKeyIdInvalid(string keyId) =>
        string.IsNullOrWhiteSpace(keyId);

    private static bool IsOptionsNull(CryptoKeyOptions options) =>
        options is null;

    private static bool IsOperationInvalid(CryptoKeyOptions options) =>
        options.Operation == 0;

    private static bool IsBlockModePaddingInvalid(CryptoKeyOptions options) =>
        options.BlockMode == BlockMode.Gcm && options.Padding != Padding.None;

    private static bool IsEcEncryptDecryptInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Ec &&
        (options.Operation.HasFlag(CryptoOperation.Encrypt) || options.Operation.HasFlag(CryptoOperation.Decrypt));

    private static bool IsAesSignVerifyInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Aes &&
        (options.Operation.HasFlag(CryptoOperation.Sign) || options.Operation.HasFlag(CryptoOperation.Verify));

    private static bool IsAesBlockPaddingInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Aes &&
        (options.BlockMode == BlockMode.None || options.Padding == Padding.None);

    private static bool IsRsaOaepBlockModeInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Rsa &&
        options.Padding == Padding.Oaep &&
        options.BlockMode != BlockMode.None;

    private static bool IsKeySizeInvalid(CryptoKeyOptions options) =>
        options.KeySize < 128 || options.KeySize > 8192;

    private static bool IsRsaKeySizeInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Rsa && options.KeySize < 2048;

    private static bool IsEcKeySizeInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Ec && options.KeySize < 256;
}