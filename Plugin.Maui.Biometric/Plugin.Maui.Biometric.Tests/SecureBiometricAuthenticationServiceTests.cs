using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class SecureBiometricAuthenticationServiceTests
{
    [Fact]
    public void Default_IsNotNull()
    {
        Assert.NotNull(SecureBiometricAuthenticationService.Default);
    }

    [Fact]
    public void Default_ReturnsSameInstance()
    {
        var first  = SecureBiometricAuthenticationService.Default;
        var second = SecureBiometricAuthenticationService.Default;

        Assert.Same(first, second);
    }

    [Fact]
    public void Default_ImplementsISecureBiometricInterface()
    {
        Assert.IsAssignableFrom<ISecureBiometric>(SecureBiometricAuthenticationService.Default);
    }

    // On net10.0 (no platform), the fallback .net implementation is used.
    // These tests verify that the fallback correctly throws NotImplementedException.

    [Fact]
    public async Task Default_CreateKeyAsync_Throws_OnUnsupportedPlatform()
    {
        await Assert.ThrowsAsync<NotImplementedException>(
            () => SecureBiometricAuthenticationService.Default.CreateKeyAsync(
                "test", new CryptoKeyOptions()));
    }

    [Fact]
    public async Task Default_DeleteKeyAsync_Throws_OnUnsupportedPlatform()
    {
        await Assert.ThrowsAsync<NotImplementedException>(
            () => SecureBiometricAuthenticationService.Default.DeleteKeyAsync("test"));
    }

    [Fact]
    public async Task Default_KeyExistsAsync_Throws_OnUnsupportedPlatform()
    {
        await Assert.ThrowsAsync<NotImplementedException>(
            () => SecureBiometricAuthenticationService.Default.KeyExistsAsync("test"));
    }

    [Fact]
    public async Task Default_EncryptAsync_Throws_OnUnsupportedPlatform()
    {
        var request = new SecureAuthenticationRequest
        {
            KeyId     = "test",
            InputData = [1, 2, 3]
        };

        await Assert.ThrowsAsync<NotImplementedException>(
            () => SecureBiometricAuthenticationService.Default.EncryptAsync(
                request, CancellationToken.None));
    }

    [Fact]
    public async Task Default_DecryptAsync_Throws_OnUnsupportedPlatform()
    {
        var request = new SecureAuthenticationRequest
        {
            KeyId     = "test",
            InputData = [1, 2, 3]
        };

        await Assert.ThrowsAsync<NotImplementedException>(
            () => SecureBiometricAuthenticationService.Default.DecryptAsync(
                request, CancellationToken.None));
    }
}
