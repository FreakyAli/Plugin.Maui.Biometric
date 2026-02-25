using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Tests every validation rule in <see cref="KeyCreationHelpers.PerformKeyCreationValidation"/>.
/// Rules are checked in declaration order inside <c>GetValidationFailure</c>.
/// </summary>
public class KeyCreationHelpersTests
{
    // ── Helpers ──────────────────────────────────────────────────────────────

    /// A minimal valid AES-GCM options object that passes all validation rules.
    private static CryptoKeyOptions ValidAes() => new()
    {
        Algorithm  = KeyAlgorithm.Aes,
        Operation  = CryptoOperation.Encrypt | CryptoOperation.Decrypt,
        KeySize    = 256,
        BlockMode  = BlockMode.Gcm,
        Padding    = Padding.None
    };

    /// A minimal valid EC-Sign options object.
    private static CryptoKeyOptions ValidEc() => new()
    {
        Algorithm  = KeyAlgorithm.Ec,
        Operation  = CryptoOperation.Sign | CryptoOperation.Verify,
        KeySize    = 256,
        BlockMode  = BlockMode.None,
        Padding    = Padding.None
    };

    /// A minimal valid RSA-Sign options object.
    private static CryptoKeyOptions ValidRsa() => new()
    {
        Algorithm  = KeyAlgorithm.Rsa,
        Operation  = CryptoOperation.Sign | CryptoOperation.Verify,
        KeySize    = 2048,
        BlockMode  = BlockMode.None,
        Padding    = Padding.None
    };

    private static KeyOperationResult Validate(string keyId, CryptoKeyOptions options)
        => KeyCreationHelpers.PerformKeyCreationValidation(keyId, options);

    // ── Rule 1: KeyId must not be null / empty / whitespace ──────────────────

    [Fact]
    public void NullKeyId_ReturnsFailure()
    {
        var result = Validate(null!, ValidAes());

        Assert.False(result.WasSuccessful);
        Assert.Contains("KeyId", result.ErrorMessage);
    }

    [Fact]
    public void EmptyKeyId_ReturnsFailure()
    {
        var result = Validate("", ValidAes());

        Assert.False(result.WasSuccessful);
    }

    [Fact]
    public void WhitespaceKeyId_ReturnsFailure()
    {
        var result = Validate("   ", ValidAes());

        Assert.False(result.WasSuccessful);
    }

    // ── Rule 2: Options must not be null ─────────────────────────────────────

    [Fact]
    public void NullOptions_ReturnsFailure()
    {
        var result = Validate("key", null!);

        Assert.False(result.WasSuccessful);
        Assert.Contains("null", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ── Rule 3: At least one operation must be set ───────────────────────────

    [Fact]
    public void NoOperation_ReturnsFailure()
    {
        var options = ValidAes();
        options.Operation = CryptoOperation.None;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("operation", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    // ── Rule 4: GCM mode cannot be used with padding ─────────────────────────

    [Theory]
    [InlineData(Padding.Pkcs7)]
    [InlineData(Padding.Pkcs1)]
    [InlineData(Padding.Oaep)]
    public void GcmWithNonNonePadding_ReturnsFailure(Padding padding)
    {
        var options = ValidAes();
        options.BlockMode = BlockMode.Gcm;
        options.Padding   = padding;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("GCM", result.ErrorMessage);
    }

    [Fact]
    public void GcmWithNonePadding_IsNotBlockedByRule4()
    {
        var options = ValidAes(); // already GCM + None

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 5: EC keys cannot be used for Encrypt / Decrypt ─────────────────

    [Theory]
    [InlineData(CryptoOperation.Encrypt)]
    [InlineData(CryptoOperation.Decrypt)]
    [InlineData(CryptoOperation.Encrypt | CryptoOperation.Decrypt)]
    public void EcWithEncryptOrDecrypt_ReturnsFailure(CryptoOperation operation)
    {
        var options = ValidEc();
        options.Operation = operation;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("EC", result.ErrorMessage);
    }

    [Fact]
    public void EcWithSignVerify_Succeeds()
    {
        var result = Validate("key", ValidEc());

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 6: AES keys cannot be used for Sign / Verify ────────────────────

    [Theory]
    [InlineData(CryptoOperation.Sign)]
    [InlineData(CryptoOperation.Verify)]
    [InlineData(CryptoOperation.Sign | CryptoOperation.Verify)]
    public void AesWithSignOrVerify_ReturnsFailure(CryptoOperation operation)
    {
        var options = ValidAes();
        options.Operation = operation;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("AES", result.ErrorMessage);
    }

    // ── Rule 7: AES requires a BlockMode; non-GCM requires padding ───────────

    [Fact]
    public void AesWithNoBlockMode_ReturnsFailure()
    {
        var options = ValidAes();
        options.BlockMode = BlockMode.None;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("BlockMode", result.ErrorMessage);
    }

    [Theory]
    [InlineData(BlockMode.Cbc)]
    [InlineData(BlockMode.Ctr)]
    [InlineData(BlockMode.Ecb)]
    public void AesWithNonGcmBlockModeAndNoPadding_ReturnsFailure(BlockMode blockMode)
    {
        var options = ValidAes();
        options.BlockMode = blockMode;
        options.Padding   = Padding.None;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
    }

    [Fact]
    public void AesWithCbcAndPkcs7_Succeeds()
    {
        var options = ValidAes();
        options.BlockMode = BlockMode.Cbc;
        options.Padding   = Padding.Pkcs7;

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 8: RSA with OAEP cannot have a BlockMode ────────────────────────

    // Note: BlockMode.Gcm is excluded here because RSA + OAEP + GCM hits Rule 4
    // ("GCM cannot be used with padding") before reaching Rule 8.
    [Theory]
    [InlineData(BlockMode.Cbc)]
    [InlineData(BlockMode.Ctr)]
    [InlineData(BlockMode.Ecb)]
    public void RsaWithOaepAndNonNoneBlockMode_ReturnsFailure(BlockMode blockMode)
    {
        var options = ValidRsa();
        options.Padding   = Padding.Oaep;
        options.BlockMode = blockMode;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("OAEP", result.ErrorMessage);
    }

    [Fact]
    public void RsaWithOaepAndNoBlockMode_Succeeds()
    {
        var options = ValidRsa();
        options.Operation = CryptoOperation.Encrypt | CryptoOperation.Decrypt;
        options.Padding   = Padding.Oaep;
        options.BlockMode = BlockMode.None;

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 9: Key size must be between 128 and 8192 bits ───────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(64)]
    [InlineData(127)]
    public void KeySizeBelowMinimum_ReturnsFailure(int keySize)
    {
        var options = ValidAes();
        options.KeySize = keySize;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("128", result.ErrorMessage);
    }

    [Fact]
    public void KeySizeAboveMaximum_ReturnsFailure()
    {
        var options = ValidAes();
        options.KeySize = 8193;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("8192", result.ErrorMessage);
    }

    [Fact]
    public void KeySizeAtMinimumBoundary_Succeeds()
    {
        var options = ValidAes();
        options.KeySize = 128;

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public void KeySizeAtMaximumBoundary_Succeeds()
    {
        // Use RSA so the RSA min-size rule (2048) doesn't interfere
        var options = ValidRsa();
        options.KeySize = 8192;

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 10: RSA key size must be at least 2048 bits ─────────────────────

    [Theory]
    [InlineData(128)]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2047)]
    public void RsaWithKeyBelowMinimum_ReturnsFailure(int keySize)
    {
        var options = ValidRsa();
        options.KeySize = keySize;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("2048", result.ErrorMessage);
    }

    [Fact]
    public void RsaWithKeyAtMinimum_Succeeds()
    {
        var options = ValidRsa();
        options.KeySize = 2048;

        var result = Validate("key", options);

        Assert.True(result.WasSuccessful);
    }

    // ── Rule 11: EC key size must be at least 256 bits ───────────────────────

    [Theory]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(255)]
    public void EcWithKeyBelowMinimum_ReturnsFailure(int keySize)
    {
        var options = ValidEc();
        options.KeySize = keySize;

        var result = Validate("key", options);

        Assert.False(result.WasSuccessful);
        Assert.Contains("256", result.ErrorMessage);
    }

    [Fact]
    public void EcWithKeyAtMinimum_Succeeds()
    {
        var result = Validate("key", ValidEc()); // KeySize = 256

        Assert.True(result.WasSuccessful);
    }

    // ── Happy paths ───────────────────────────────────────────────────────────

    [Fact]
    public void ValidAesGcm_Succeeds()
    {
        var result = Validate("my-aes-key", ValidAes());

        Assert.True(result.WasSuccessful);
        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void ValidEcSign_Succeeds()
    {
        var result = Validate("my-ec-key", ValidEc());

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public void ValidRsaSign_Succeeds()
    {
        var result = Validate("my-rsa-key", ValidRsa());

        Assert.True(result.WasSuccessful);
    }
}
