using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class BiometricAuthenticationServiceTests
{
    [Fact]
    public void Default_IsNotNull()
    {
        Assert.NotNull(BiometricAuthenticationService.Default);
    }

    [Fact]
    public void Default_ReturnsSameInstance()
    {
        var first = BiometricAuthenticationService.Default;
        var second = BiometricAuthenticationService.Default;

        Assert.Same(first, second);
    }

    [Fact]
    public void Default_ImplementsIBiometricInterface()
    {
        Assert.IsAssignableFrom<IBiometric>(BiometricAuthenticationService.Default);
    }

    // On net10.0 (no platform), the fallback implementation is used.
    // These tests verify that the fallback correctly reports no support.

    [Fact]
    public void Default_IsPlatformSupported_ReturnsFalse_OnUnsupportedPlatform()
    {
        Assert.False(BiometricAuthenticationService.Default.IsPlatformSupported);
    }

    [Fact]
    public async Task Default_GetAuthenticationStatusAsync_Throws_OnUnsupportedPlatform()
    {
        await Assert.ThrowsAsync<NotImplementedException>(
            () => BiometricAuthenticationService.Default.GetAuthenticationStatusAsync());
    }

    [Fact]
    public async Task Default_AuthenticateAsync_Throws_OnUnsupportedPlatform()
    {
        var request = new AuthenticationRequest { Title = "Test" };

        await Assert.ThrowsAsync<NotImplementedException>(
            () => BiometricAuthenticationService.Default.AuthenticateAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task Default_GetEnrolledBiometricTypesAsync_Throws_OnUnsupportedPlatform()
    {
        await Assert.ThrowsAsync<NotImplementedException>(
            () => BiometricAuthenticationService.Default.GetEnrolledBiometricTypesAsync());
    }
}
