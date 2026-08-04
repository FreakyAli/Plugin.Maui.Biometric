using System.Security.Cryptography;
using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Tests the cross-platform AES-GCM helper that is shared between Apple and Windows implementations.
/// Verifies the encrypt→decrypt round-trip, output format, and error handling.
/// </summary>
public class AesGcmHelpersTests
{
    private static byte[] GenerateKey(int bits = 256) =>
        RandomNumberGenerator.GetBytes(bits / 8);

    // ── Encrypt ──────────────────────────────────────────────────────────────

    [Fact]
    public void Encrypt_ReturnsSuccess()
    {
        var key = GenerateKey();
        var plaintext = "Hello, Secure World!"u8.ToArray();

        var result = AesGcmHelpers.Encrypt(key, plaintext);

        Assert.True(result.WasSuccessful);
        Assert.NotNull(result.OutputData);
        Assert.NotNull(result.IV);
    }

    [Fact]
    public void Encrypt_OutputData_ContainsCiphertextPlusTag()
    {
        var key = GenerateKey();
        var plaintext = new byte[32];

        var result = AesGcmHelpers.Encrypt(key, plaintext);

        // Output should be ciphertext (same length as input) + 16-byte tag
        Assert.Equal(plaintext.Length + 16, result.OutputData!.Length);
    }

    [Fact]
    public void Encrypt_IV_Is12Bytes()
    {
        var key = GenerateKey();

        var result = AesGcmHelpers.Encrypt(key, [1, 2, 3]);

        Assert.Equal(12, result.IV!.Length);
    }

    [Fact]
    public void Encrypt_OutputData_IsNotPlaintext()
    {
        var key = GenerateKey();
        var plaintext = "This should be encrypted"u8.ToArray();

        var result = AesGcmHelpers.Encrypt(key, plaintext);

        // Ciphertext portion should differ from plaintext
        Assert.NotEqual(plaintext, result.OutputData![..plaintext.Length]);
    }

    [Fact]
    public void Encrypt_GeneratesDifferentIV_EachCall()
    {
        var key = GenerateKey();
        byte[] plaintext = [1, 2, 3];

        var result1 = AesGcmHelpers.Encrypt(key, plaintext);
        var result2 = AesGcmHelpers.Encrypt(key, plaintext);

        Assert.NotEqual(result1.IV, result2.IV);
    }

    // ── Decrypt ──────────────────────────────────────────────────────────────

    [Fact]
    public void Decrypt_WithNullIV_ReturnsFailure()
    {
        var key = GenerateKey();

        var result = AesGcmHelpers.Decrypt(key, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], null);

        Assert.False(result.WasSuccessful);
        Assert.Contains("IV is required", result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_WithEmptyIV_ReturnsFailure()
    {
        var key = GenerateKey();

        var result = AesGcmHelpers.Decrypt(key, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17], Array.Empty<byte>());

        Assert.False(result.WasSuccessful);
        Assert.Contains("IV is required", result.ErrorMessage);
    }

    [Fact]
    public void Decrypt_WithInputTooShort_ReturnsFailure()
    {
        var key = GenerateKey();

        var result = AesGcmHelpers.Decrypt(key, new byte[15], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        Assert.False(result.WasSuccessful);
        Assert.Contains("too short", result.ErrorMessage);
    }

    // ── Round-trip ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(256)]
    public void RoundTrip_EncryptThenDecrypt_RecoverPlaintext(int keyBits)
    {
        var key = GenerateKey(keyBits);
        var plaintext = "Round-trip test data for AES-GCM"u8.ToArray();

        var encrypted = AesGcmHelpers.Encrypt(key, plaintext);
        Assert.True(encrypted.WasSuccessful);

        var decrypted = AesGcmHelpers.Decrypt(key, encrypted.OutputData!, encrypted.IV);
        Assert.True(decrypted.WasSuccessful);
        Assert.Equal(plaintext, decrypted.OutputData);
    }

    [Fact]
    public void RoundTrip_EmptyPlaintext_Works()
    {
        var key = GenerateKey();
        var plaintext = Array.Empty<byte>();

        var encrypted = AesGcmHelpers.Encrypt(key, plaintext);
        Assert.True(encrypted.WasSuccessful);

        var decrypted = AesGcmHelpers.Decrypt(key, encrypted.OutputData!, encrypted.IV);
        Assert.True(decrypted.WasSuccessful);
        Assert.Equal(plaintext, decrypted.OutputData);
    }

    [Fact]
    public void RoundTrip_LargeData_Works()
    {
        var key = GenerateKey();
        var plaintext = RandomNumberGenerator.GetBytes(10_000);

        var encrypted = AesGcmHelpers.Encrypt(key, plaintext);
        Assert.True(encrypted.WasSuccessful);

        var decrypted = AesGcmHelpers.Decrypt(key, encrypted.OutputData!, encrypted.IV);
        Assert.True(decrypted.WasSuccessful);
        Assert.Equal(plaintext, decrypted.OutputData);
    }

    [Fact]
    public void RoundTrip_WrongKey_FailsDecryption()
    {
        var key1 = GenerateKey();
        var key2 = GenerateKey();
        var plaintext = "Secret data"u8.ToArray();

        var encrypted = AesGcmHelpers.Encrypt(key1, plaintext);
        Assert.True(encrypted.WasSuccessful);

        // Decrypting with a different key should throw (AesGcm throws AuthenticationTagMismatchException)
        Assert.ThrowsAny<Exception>(() =>
            AesGcmHelpers.Decrypt(key2, encrypted.OutputData!, encrypted.IV));
    }

    [Fact]
    public void RoundTrip_TamperedCiphertext_FailsDecryption()
    {
        var key = GenerateKey();
        var plaintext = "Tamper test"u8.ToArray();

        var encrypted = AesGcmHelpers.Encrypt(key, plaintext);
        Assert.True(encrypted.WasSuccessful);

        // Tamper with the first byte of ciphertext
        var tampered = (byte[])encrypted.OutputData!.Clone();
        tampered[0] ^= 0xFF;

        Assert.ThrowsAny<Exception>(() =>
            AesGcmHelpers.Decrypt(key, tampered, encrypted.IV));
    }

    // ── Cross-platform format compatibility ───────────────────────────────────

    [Fact]
    public void OutputFormat_CiphertextThenTag_Is_CrossPlatformCompatible()
    {
        // Verify the output format: ciphertext || 16-byte GCM tag
        // This format must match Android's Cipher.doFinal GCM output
        var key = GenerateKey();
        var plaintext = new byte[42]; // arbitrary size

        var encrypted = AesGcmHelpers.Encrypt(key, plaintext);
        Assert.True(encrypted.WasSuccessful);

        // Total = ciphertext(42) + tag(16) = 58
        Assert.Equal(plaintext.Length + 16, encrypted.OutputData!.Length);

        // IV must be 12 bytes (96-bit, NIST recommended for GCM)
        Assert.Equal(12, encrypted.IV!.Length);
    }
}
