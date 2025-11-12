namespace Plugin.Maui.Biometric;

public interface IBiometric
{
    Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    Task<BiometricType[]> GetEnrolledBiometricTypesAsync();

    [Obsolete("This property is now obselete since the library now supports all platforms.")]
    bool IsPlatformSupported { get; }
}