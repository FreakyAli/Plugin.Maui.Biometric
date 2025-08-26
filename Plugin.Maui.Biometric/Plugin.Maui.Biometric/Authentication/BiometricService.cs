namespace Plugin.Maui.Biometric;

internal partial class BiometricService : IBiometric
{
    public bool IsPlatformSupported { get; } = GetIsPlatformSupported();

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync();

    private static partial bool GetIsPlatformSupported();
}