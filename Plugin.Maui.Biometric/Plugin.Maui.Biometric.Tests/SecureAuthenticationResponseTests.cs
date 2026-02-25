using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class SecureAuthenticationResponseTests
{
    // Success factory

    [Fact]
    public void Success_WasSuccessful_IsTrue()
    {
        var response = SecureAuthenticationResponse.Success([1, 2, 3]);

        Assert.True(response.WasSuccessful);
    }

    [Fact]
    public void Success_SetsOutputData()
    {
        byte[] data = [10, 20, 30];
        var response = SecureAuthenticationResponse.Success(data);

        Assert.Equal(data, response.OutputData);
    }

    [Fact]
    public void Success_ClonesOutputData_MutatingOriginalDoesNotAffectResponse()
    {
        byte[] data = [1, 2, 3];
        var response = SecureAuthenticationResponse.Success(data);

        data[0] = 99;

        Assert.Equal(1, response.OutputData![0]);
    }

    [Fact]
    public void Success_WithIv_SetsIv()
    {
        byte[] iv = [0xAA, 0xBB, 0xCC];
        var response = SecureAuthenticationResponse.Success([], iv);

        Assert.Equal(iv, response.IV);
    }

    [Fact]
    public void Success_ClonesIv_MutatingOriginalDoesNotAffectResponse()
    {
        byte[] iv = [0xAA, 0xBB];
        var response = SecureAuthenticationResponse.Success([], iv);

        iv[0] = 0xFF;

        Assert.Equal(0xAA, response.IV![0]);
    }

    [Fact]
    public void Success_WithNullIv_IvIsNull()
    {
        var response = SecureAuthenticationResponse.Success([1, 2], iv: null);

        Assert.Null(response.IV);
    }

    [Fact]
    public void Success_ErrorMessage_IsNull()
    {
        var response = SecureAuthenticationResponse.Success([]);

        Assert.Null(response.ErrorMessage);
    }

    // Failure factory

    [Fact]
    public void Failure_WasSuccessful_IsFalse()
    {
        var response = SecureAuthenticationResponse.Failure("Decryption failed");

        Assert.False(response.WasSuccessful);
    }

    [Fact]
    public void Failure_SetsErrorMessage()
    {
        const string msg = "Invalid key";
        var response = SecureAuthenticationResponse.Failure(msg);

        Assert.Equal(msg, response.ErrorMessage);
    }

    [Fact]
    public void Failure_OutputData_IsNull()
    {
        var response = SecureAuthenticationResponse.Failure("Error");

        Assert.Null(response.OutputData);
    }

    [Fact]
    public void Failure_Iv_IsNull()
    {
        var response = SecureAuthenticationResponse.Failure("Error");

        Assert.Null(response.IV);
    }

    // IV has a public setter (can be updated after creation)

    [Fact]
    public void IV_PublicSetter_CanBeUpdated()
    {
        var response = SecureAuthenticationResponse.Success([1, 2, 3]);
        byte[] newIv = [0x01, 0x02];

        response.IV = newIv;

        Assert.Equal(newIv, response.IV);
    }
}
