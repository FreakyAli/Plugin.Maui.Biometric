namespace Plugin.Maui.Biometric;

public class KeyCreationHelpers
{
    public static KeyOperationResult PerformKeyCreationValidation(string keyId, CryptoKeyOptions options)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return KeyOperationResult.Failure("KeyId cannot be null or empty.");
        }

        if (options is null)
        {
            return KeyOperationResult.Failure("Options cannot be null.");
        }

        if (options.Operation == 0)
        {
            return KeyOperationResult.Failure("At least one operation must be specified.");
        }

        if (options.BlockMode == BlockMode.Gcm && options.Padding != Padding.None)
        {
            return KeyOperationResult.Failure("GCM mode cannot be used with padding. Set Padding to None.");
        }

        if (options.Algorithm == KeyAlgorithm.Ec && (options.Operation.HasFlag(CryptoOperation.Encrypt) || options.Operation.HasFlag(CryptoOperation.Decrypt)))
        {
            return KeyOperationResult.Failure("EC keys cannot be used for encrypt/decrypt operations. Use RSA or AES instead.");
        }

        if (options.Algorithm == KeyAlgorithm.Aes && (options.Operation.HasFlag(CryptoOperation.Sign) || options.Operation.HasFlag(CryptoOperation.Verify)))
        {
            return KeyOperationResult.Failure("AES keys cannot be used for sign/verify operations. Use RSA or EC instead.");
        }

        if (options.Algorithm == KeyAlgorithm.Aes && (options.BlockMode == BlockMode.None || options.Padding == Padding.None))
        {
            return KeyOperationResult.Failure("AES keys require a valid BlockMode and Padding.");
        }

        if (options.Algorithm == KeyAlgorithm.Rsa && options.Padding == Padding.Oaep && options.BlockMode != BlockMode.None)
        {
            return KeyOperationResult.Failure("RSA with OAEP padding cannot be used with a BlockMode. Set BlockMode to None.");
        }

        if (options.KeySize < 128 || options.KeySize > 8192)
        {
            return KeyOperationResult.Failure("Key size must be between 128 and 8192 bits.");
        }

        if (options.Algorithm == KeyAlgorithm.Rsa && options.KeySize < 2048)
        {
            return KeyOperationResult.Failure("RSA key size must be at least 2048 bits.");
        }

        return KeyOperationResult.Success();
    }
}
