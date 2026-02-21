using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class AuthenticationRequestTests
{
    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var request = new AuthenticationRequest();

        Assert.False(request.AllowPasswordAuth);
        Assert.Null(request.Title);
        Assert.Null(request.Subtitle);
        Assert.Null(request.NegativeText);
        Assert.Null(request.Description);
        Assert.Equal(AuthenticatorStrength.Strong, request.AuthStrength);
    }

    [Fact]
    public void AllProperties_CanBeSet()
    {
        var request = new AuthenticationRequest
        {
            AllowPasswordAuth = true,
            Title = "Authenticate",
            Subtitle = "Use your fingerprint",
            NegativeText = "Cancel",
            Description = "Please authenticate to continue",
            AuthStrength = AuthenticatorStrength.Weak
        };

        Assert.True(request.AllowPasswordAuth);
        Assert.Equal("Authenticate", request.Title);
        Assert.Equal("Use your fingerprint", request.Subtitle);
        Assert.Equal("Cancel", request.NegativeText);
        Assert.Equal("Please authenticate to continue", request.Description);
        Assert.Equal(AuthenticatorStrength.Weak, request.AuthStrength);
    }

    [Theory]
    [InlineData(AuthenticatorStrength.Strong)]
    [InlineData(AuthenticatorStrength.Weak)]
    public void AuthStrength_AcceptsAllValues(AuthenticatorStrength strength)
    {
        var request = new AuthenticationRequest { AuthStrength = strength };
        Assert.Equal(strength, request.AuthStrength);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AllowPasswordAuth_CanBeToggled(bool allow)
    {
        var request = new AuthenticationRequest { AllowPasswordAuth = allow };
        Assert.Equal(allow, request.AllowPasswordAuth);
    }
}
