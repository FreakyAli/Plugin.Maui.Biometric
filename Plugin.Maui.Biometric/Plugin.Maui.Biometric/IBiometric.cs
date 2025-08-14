namespace Plugin.Maui.Biometric;

[Preserve(AllMembers = true)]
public interface IBiometric : IDisposable
{
    Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    Task<BiometricType[]> GetEnrolledBiometricTypesAsync();

    bool IsPlatformSupported { get; }
}