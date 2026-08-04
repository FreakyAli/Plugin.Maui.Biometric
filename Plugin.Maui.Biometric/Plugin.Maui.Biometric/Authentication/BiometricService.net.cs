namespace Plugin.Maui.Biometric;
internal partial class BiometricService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        throw new PlatformNotSupportedException("Biometric authentication is not supported on this platform.");
    }

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        throw new PlatformNotSupportedException("Biometric authentication is not supported on this platform.");
    }

    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
    {
        throw new PlatformNotSupportedException("Biometric authentication is not supported on this platform.");
    }

    private static partial bool GetIsPlatformSupported() => false;
}