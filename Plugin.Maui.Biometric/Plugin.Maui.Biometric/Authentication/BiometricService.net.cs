namespace Plugin.Maui.Biometric;
internal partial class BiometricService : IBiometric
{
    private static readonly PlatformNotSupportedException s_notSupported =
        new("Biometric authentication is not supported on this platform.");

    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
        => Task.FromException<AuthenticationResponse>(s_notSupported);

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
        => Task.FromException<BiometricHwStatus>(s_notSupported);

    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
        => Task.FromException<BiometricType[]>(s_notSupported);

    private static partial bool GetIsPlatformSupported() => false;
}
