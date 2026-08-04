using System.Security.Cryptography;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Cross-platform AES-GCM encrypt/decrypt helper.
/// Output format: <c>ciphertext ‖ 16-byte GCM auth tag</c>, IV returned separately.
/// This matches the GCM output layout produced by Android's <c>Cipher.doFinal</c>,
/// so payloads are cross-platform compatible between Android, Apple, and Windows.
/// </summary>
internal static class AesGcmHelpers
{
    private const int NonceSize = 12;   // 96-bit nonce (NIST recommended)
    private const int TagSize = 16;     // 128-bit authentication tag

    /// <summary>
    /// Encrypts <paramref name="inputData"/> using AES-GCM.
    /// Returns a response with <c>OutputData = ciphertext ‖ tag</c> and <c>IV = 12-byte nonce</c>.
    /// </summary>
    internal static SecureAuthenticationResponse Encrypt(byte[] keyBytes, byte[] inputData)
    {
        var iv         = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[inputData.Length];
        var tag        = new byte[TagSize];

        using var aesGcm = new AesGcm(keyBytes, TagSize);
        aesGcm.Encrypt(iv, inputData, ciphertext, tag);

        // Append tag to ciphertext — matches Android Cipher GCM output layout.
        var outputData = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(outputData, 0);
        tag.CopyTo(outputData, ciphertext.Length);

        return SecureAuthenticationResponse.Success(outputData, iv);
    }

    /// <summary>
    /// Decrypts <paramref name="inputData"/> (format: <c>ciphertext ‖ 16-byte tag</c>)
    /// using AES-GCM with the given <paramref name="iv"/>.
    /// </summary>
    internal static SecureAuthenticationResponse Decrypt(byte[] keyBytes, byte[] inputData, byte[]? iv)
    {
        if (iv is null || iv.Length == 0)
            return SecureAuthenticationResponse.Failure("IV is required for AES-GCM decryption.");

        if (inputData.Length < TagSize)
            return SecureAuthenticationResponse.Failure("Input data is too short for AES-GCM decryption.");

        // Split ciphertext and 16-byte tag
        var ciphertext = inputData[..^TagSize];
        var tag        = inputData[^TagSize..];
        var plaintext  = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(keyBytes, TagSize);
        aesGcm.Decrypt(iv, ciphertext, tag, plaintext);

        return SecureAuthenticationResponse.Success(plaintext);
    }
}
