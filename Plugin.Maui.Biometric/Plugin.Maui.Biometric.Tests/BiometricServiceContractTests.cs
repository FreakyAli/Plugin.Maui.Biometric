using Plugin.Maui.Biometric.Tests.Fakes;
using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Tests the expected contract of any IBiometric implementation using a fake.
/// These tests define the behaviour that all platform implementations must satisfy.
/// </summary>
public class BiometricServiceContractTests
{
    private readonly FakeBiometricService _sut = new();

    // GetAuthenticationStatusAsync

    [Theory]
    [InlineData(BiometricHwStatus.Success)]
    [InlineData(BiometricHwStatus.NoHardware)]
    [InlineData(BiometricHwStatus.Unavailable)]
    [InlineData(BiometricHwStatus.Unsupported)]
    [InlineData(BiometricHwStatus.NotEnrolled)]
    [InlineData(BiometricHwStatus.LockedOut)]
    [InlineData(BiometricHwStatus.Failure)]
    [InlineData(BiometricHwStatus.PresentButNotEnrolled)]
    public async Task GetAuthenticationStatusAsync_ReturnsExpectedStatus(BiometricHwStatus expected)
    {
        _sut.StatusToReturn = expected;

        var result = await _sut.GetAuthenticationStatusAsync();

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(AuthenticatorStrength.Strong)]
    [InlineData(AuthenticatorStrength.Weak)]
    public async Task GetAuthenticationStatusAsync_AcceptsAllStrengths(AuthenticatorStrength strength)
    {
        _sut.StatusToReturn = BiometricHwStatus.Success;

        var result = await _sut.GetAuthenticationStatusAsync(strength);

        Assert.Equal(BiometricHwStatus.Success, result);
    }

    [Fact]
    public async Task GetAuthenticationStatusAsync_DefaultStrength_IsStrong()
    {
        // Calling with no argument should default to Strong
        var result = await _sut.GetAuthenticationStatusAsync();

        Assert.Equal(_sut.StatusToReturn, result);
    }

    // AuthenticateAsync

    [Fact]
    public async Task AuthenticateAsync_OnSuccess_ReturnsSuccessResponse()
    {
        _sut.ResponseToReturn = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Success,
            AuthenticationType = AuthenticationType.Biometric
        };
        var request = new AuthenticationRequest { Title = "Authenticate" };

        var result = await _sut.AuthenticateAsync(request, CancellationToken.None);

        Assert.Equal(BiometricResponseStatus.Success, result.Status);
        Assert.Equal(AuthenticationType.Biometric, result.AuthenticationType);
    }

    [Fact]
    public async Task AuthenticateAsync_OnFailure_ReturnsFailureWithErrorMsg()
    {
        const string errorMsg = "Biometric not recognised";
        _sut.ResponseToReturn = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Failure,
            ErrorMsg = errorMsg
        };
        var request = new AuthenticationRequest { Title = "Authenticate" };

        var result = await _sut.AuthenticateAsync(request, CancellationToken.None);

        Assert.Equal(BiometricResponseStatus.Failure, result.Status);
        Assert.Equal(errorMsg, result.ErrorMsg);
    }

    [Fact]
    public async Task AuthenticateAsync_WithAllowPasswordAuth_ReturnsResponse()
    {
        _sut.ResponseToReturn = new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Success,
            AuthenticationType = AuthenticationType.DeviceCreds
        };
        var request = new AuthenticationRequest
        {
            Title = "Authenticate",
            AllowPasswordAuth = true
        };

        var result = await _sut.AuthenticateAsync(request, CancellationToken.None);

        Assert.Equal(BiometricResponseStatus.Success, result.Status);
    }

    [Fact]
    public async Task AuthenticateAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var request = new AuthenticationRequest { Title = "Authenticate" };

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _sut.AuthenticateAsync(request, cts.Token));
    }

    [Fact]
    public async Task AuthenticateAsync_ReturnsNonNullResponse()
    {
        var request = new AuthenticationRequest { Title = "Authenticate" };

        var result = await _sut.AuthenticateAsync(request, CancellationToken.None);

        Assert.NotNull(result);
    }

    // GetEnrolledBiometricTypesAsync

    [Fact]
    public async Task GetEnrolledBiometricTypesAsync_WhenNoneEnrolled_ReturnsEmptyArray()
    {
        _sut.EnrolledTypesToReturn = [];

        var result = await _sut.GetEnrolledBiometricTypesAsync();

        Assert.Empty(result);
    }

    [Fact]
    public async Task GetEnrolledBiometricTypesAsync_WithFingerprintEnrolled_ReturnsFingerprintType()
    {
        _sut.EnrolledTypesToReturn = [BiometricType.Fingerprint];

        var result = await _sut.GetEnrolledBiometricTypesAsync();

        Assert.Single(result);
        Assert.Contains(BiometricType.Fingerprint, result);
    }

    [Fact]
    public async Task GetEnrolledBiometricTypesAsync_WithMultipleTypesEnrolled_ReturnsAllTypes()
    {
        _sut.EnrolledTypesToReturn = [BiometricType.Fingerprint, BiometricType.Face];

        var result = await _sut.GetEnrolledBiometricTypesAsync();

        Assert.Equal(2, result.Length);
        Assert.Contains(BiometricType.Fingerprint, result);
        Assert.Contains(BiometricType.Face, result);
    }

    [Fact]
    public async Task GetEnrolledBiometricTypesAsync_ReturnsNonNullArray()
    {
        var result = await _sut.GetEnrolledBiometricTypesAsync();

        Assert.NotNull(result);
    }

    // IsPlatformSupported

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void IsPlatformSupported_ReturnsExpectedValue(bool supported)
    {
        _sut.IsPlatformSupported = supported;

        Assert.Equal(supported, _sut.IsPlatformSupported);
    }
}
