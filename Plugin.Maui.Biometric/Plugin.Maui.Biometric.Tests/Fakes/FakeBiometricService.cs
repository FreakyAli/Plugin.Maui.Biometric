namespace Plugin.Maui.Biometric.Tests.Fakes;

internal class FakeBiometricService : IBiometric
{
    public BiometricHwStatus StatusToReturn { get; set; } = BiometricHwStatus.Success;

    public AuthenticationResponse ResponseToReturn { get; set; } = new() { Status = BiometricResponseStatus.Success };

    public BiometricType[] EnrolledTypesToReturn { get; set; } = [];

    public bool IsPlatformSupported { get; set; } = true;

    public Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong)
        => Task.FromResult(StatusToReturn);

    public Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(ResponseToReturn);
    }

    public Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
        => Task.FromResult(EnrolledTypesToReturn);
}
