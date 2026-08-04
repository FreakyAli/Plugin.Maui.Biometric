using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Tests the shared Sign/Verify input validation methods on <see cref="SecureBiometricService"/>.
/// These are used by all platform implementations before dispatching to native code.
/// </summary>
public class SharedValidationTests
{
    // ── ValidateSignInput ────────────────────────────────────────────────────

    [Fact]
    public void ValidateSignInput_ValidInputs_ReturnsNull()
    {
        var result = SecureBiometricService.ValidateSignInput("key-id", [1, 2, 3]);

        Assert.Null(result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateSignInput_NullOrEmptyKeyId_ReturnsFailure(string? keyId)
    {
        var result = SecureBiometricService.ValidateSignInput(keyId!, [1, 2, 3]);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("KeyId", result.ErrorMessage);
    }

    [Fact]
    public void ValidateSignInput_NullInputData_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateSignInput("key-id", null!);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Input data", result.ErrorMessage);
    }

    [Fact]
    public void ValidateSignInput_EmptyInputData_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateSignInput("key-id", Array.Empty<byte>());

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Input data", result.ErrorMessage);
    }

    // ── ValidateVerifyInput ──────────────────────────────────────────────────

    [Fact]
    public void ValidateVerifyInput_ValidInputs_ReturnsNull()
    {
        var result = SecureBiometricService.ValidateVerifyInput("key-id", [1, 2, 3], [4, 5, 6]);

        Assert.Null(result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateVerifyInput_NullOrEmptyKeyId_ReturnsFailure(string? keyId)
    {
        var result = SecureBiometricService.ValidateVerifyInput(keyId!, [1, 2, 3], [4, 5, 6]);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("KeyId", result.ErrorMessage);
    }

    [Fact]
    public void ValidateVerifyInput_NullInputData_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateVerifyInput("key-id", null!, [4, 5, 6]);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Input data", result.ErrorMessage);
    }

    [Fact]
    public void ValidateVerifyInput_EmptyInputData_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateVerifyInput("key-id", Array.Empty<byte>(), [4, 5, 6]);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Input data", result.ErrorMessage);
    }

    [Fact]
    public void ValidateVerifyInput_NullSignature_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateVerifyInput("key-id", [1, 2, 3], null!);

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Signature", result.ErrorMessage);
    }

    [Fact]
    public void ValidateVerifyInput_EmptySignature_ReturnsFailure()
    {
        var result = SecureBiometricService.ValidateVerifyInput("key-id", [1, 2, 3], Array.Empty<byte>());

        Assert.NotNull(result);
        Assert.False(result.WasSuccessful);
        Assert.Contains("Signature", result.ErrorMessage);
    }
}
