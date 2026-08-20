namespace Plugin.Maui.Biometric;

public interface IBiometric
{
    Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    Task<BiometricType[]> GetEnrolledBiometricTypesAsync();

    [Obsolete("This property is obsolete. Use GetAuthenticationStatusAsync to check biometric availability; unsupported platforms throw PlatformNotSupportedException.")]
    bool IsPlatformSupported { get; }
}