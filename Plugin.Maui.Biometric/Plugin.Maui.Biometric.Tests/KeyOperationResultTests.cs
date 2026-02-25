using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class KeyOperationResultTests
{
    // Success factory

    [Fact]
    public void Success_WasSuccessful_IsTrue()
    {
        var result = KeyOperationResult.Success();

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public void Success_WithNoArguments_ErrorMessageIsNull()
    {
        var result = KeyOperationResult.Success();

        Assert.Null(result.ErrorMessage);
    }

    [Fact]
    public void Success_WithNoArguments_AdditionalInfoIsNull()
    {
        var result = KeyOperationResult.Success();

        Assert.Null(result.AdditionalInfo);
    }

    [Fact]
    public void Success_WithAdditionalInfo_SetsAdditionalInfo()
    {
        const string info = "Key created successfully";
        var result = KeyOperationResult.Success(additionalInfo: info);

        Assert.Equal(info, result.AdditionalInfo);
    }

    [Fact]
    public void Success_WithSecurityLevel_SetsSecurityLevelName()
    {
        const string level = "StrongBox";
        var result = KeyOperationResult.Success(securityLevelName: level);

        Assert.Equal(level, result.SecurityLevelName);
    }

    [Fact]
    public void Success_WithBothOptionalParams_SetsBoth()
    {
        var result = KeyOperationResult.Success("TEE", "Key created in TEE.");

        Assert.Equal("TEE", result.SecurityLevelName);
        Assert.Equal("Key created in TEE.", result.AdditionalInfo);
    }

    // Failure factory

    [Fact]
    public void Failure_WasSuccessful_IsFalse()
    {
        var result = KeyOperationResult.Failure("Something went wrong.");

        Assert.False(result.WasSuccessful);
    }

    [Fact]
    public void Failure_SetsErrorMessage()
    {
        const string errorMsg = "Key not found";
        var result = KeyOperationResult.Failure(errorMsg);

        Assert.Equal(errorMsg, result.ErrorMessage);
    }

    [Fact]
    public void Failure_WithAdditionalInfo_SetsAdditionalInfo()
    {
        var result = KeyOperationResult.Failure("Error", additionalInfo: "Extra details");

        Assert.Equal("Extra details", result.AdditionalInfo);
    }

    [Fact]
    public void Failure_SecurityLevelName_IsNull()
    {
        var result = KeyOperationResult.Failure("Error");

        Assert.Null(result.SecurityLevelName);
    }

    // Distinguishing success from failure

    [Fact]
    public void SuccessResult_IsNotSameAs_FailureResult()
    {
        var success = KeyOperationResult.Success();
        var failure = KeyOperationResult.Failure("Err");

        Assert.NotEqual(success.WasSuccessful, failure.WasSuccessful);
    }
}
