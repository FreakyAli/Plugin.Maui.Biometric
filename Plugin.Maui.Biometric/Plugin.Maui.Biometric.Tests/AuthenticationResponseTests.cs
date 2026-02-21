using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class AuthenticationResponseTests
{
    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var response = new AuthenticationResponse();

        Assert.Equal(BiometricResponseStatus.Failure, response.Status);
        Assert.Equal(AuthenticationType.Unknown, response.AuthenticationType);
        Assert.Null(response.ErrorMsg);
    }

    [Fact]
    public void AllProperties_CanBeSet()
    {
        var response = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Success,
            AuthenticationType = AuthenticationType.Biometric,
            ErrorMsg = "Authentication failed"
        };

        Assert.Equal(BiometricResponseStatus.Success, response.Status);
        Assert.Equal(AuthenticationType.Biometric, response.AuthenticationType);
        Assert.Equal("Authentication failed", response.ErrorMsg);
    }

    [Theory]
    [InlineData(BiometricResponseStatus.Failure)]
    [InlineData(BiometricResponseStatus.Success)]
    public void Status_AcceptsAllValues(BiometricResponseStatus status)
    {
        var response = new AuthenticationResponse { Status = status };

        Assert.Equal(status, response.Status);
    }

    [Theory]
    [InlineData(AuthenticationType.Unknown)]
    [InlineData(AuthenticationType.DeviceCreds)]
    [InlineData(AuthenticationType.Biometric)]
    [InlineData(AuthenticationType.WindowsHello)]
    public void AuthenticationType_AcceptsAllValues(AuthenticationType type)
    {
        var response = new AuthenticationResponse { AuthenticationType = type };

        Assert.Equal(type, response.AuthenticationType);
    }

    [Fact]
    public void SuccessResponse_HasNoErrorMsg()
    {
        var response = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Success,
            AuthenticationType = AuthenticationType.Biometric
        };

        Assert.Null(response.ErrorMsg);
    }

    [Fact]
    public void FailureResponse_CanHaveErrorMsg()
    {
        const string errorMessage = "Too many failed attempts";
        var response = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Failure,
            ErrorMsg = errorMessage
        };

        Assert.Equal(BiometricResponseStatus.Failure, response.Status);
        Assert.Equal(errorMessage, response.ErrorMsg);
    }
}
