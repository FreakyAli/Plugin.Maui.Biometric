namespace Plugin.Maui.Biometric;

internal class KeyCreationHelpers
{
    public static KeyOperationResult PerformKeyCreationValidation(string keyId, CryptoKeyOptions options)
    {
        var failure = GetValidationFailure(keyId, options);
        return failure ?? KeyOperationResult.Success();
    }

    // Returns null if all validations pass, or a Failure result if any rule fails.
    private static KeyOperationResult? GetValidationFailure(string keyId, CryptoKeyOptions options)
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
        if (IsAesIncompatiblePaddingInvalid(options))
            return KeyOperationResult.Failure("AES does not support OAEP or PKCS1 padding.");
        if (IsAesBlockPaddingInvalid(options))
        {
            var aesError = options.BlockMode == BlockMode.None
                ? "AES requires a BlockMode. For GCM set Padding to None; for CBC require a padding scheme (e.g., PKCS7)."
                : "AES with CBC mode requires a padding scheme (e.g., PKCS7); CTR and GCM support NoPadding.";
            return KeyOperationResult.Failure(aesError);
        }
        if (IsRsaBlockModeInvalid(options))
            return KeyOperationResult.Failure("RSA keys cannot be used with a BlockMode. Set BlockMode to None.");
        if (IsRsaIncompatiblePaddingInvalid(options))
            return KeyOperationResult.Failure("RSA does not support PKCS7 padding.");
        if (IsKeySizeInvalid(options))
        {
            var sizeError = options.Algorithm switch
            {
                KeyAlgorithm.Aes => "AES key size must be 128, 192, or 256 bits.",
                KeyAlgorithm.Rsa => "RSA key size must be 2048, 3072, or 4096 bits.",
                KeyAlgorithm.Ec => "EC key size must be 256, 384, or 521 bits.",
                _ => "Invalid key size for algorithm."
            };
            return KeyOperationResult.Failure(sizeError);
        }
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

    private static bool IsAesIncompatiblePaddingInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Aes &&
        (options.Padding == Padding.Oaep || options.Padding == Padding.Pkcs1);

    private static bool IsAesBlockPaddingInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Aes &&
        (
            options.BlockMode == BlockMode.None ||
            (options.BlockMode == BlockMode.Cbc && options.Padding == Padding.None)
        );

    private static bool IsRsaBlockModeInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Rsa &&
        options.BlockMode != BlockMode.None;

    private static bool IsRsaIncompatiblePaddingInvalid(CryptoKeyOptions options) =>
        options.Algorithm == KeyAlgorithm.Rsa &&
        options.Padding == Padding.Pkcs7;

    private static bool IsKeySizeInvalid(CryptoKeyOptions options)
    {
        return options.Algorithm switch
        {
            KeyAlgorithm.Aes => !IsValidAesKeySize(options.KeySize),
            KeyAlgorithm.Rsa => !IsValidRsaKeySize(options.KeySize),
            KeyAlgorithm.Ec => !IsValidEcKeySize(options.KeySize),
            _ => true
        };
    }

    private static bool IsValidAesKeySize(int keySize) =>
        keySize == 128 || keySize == 192 || keySize == 256;

    private static bool IsValidRsaKeySize(int keySize) =>
        keySize >= 2048 && (keySize == 2048 || keySize == 3072 || keySize == 4096);

    private static bool IsValidEcKeySize(int keySize) =>
        keySize == 256 || keySize == 384 || keySize == 521;
}