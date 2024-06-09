namespace Plugin.Maui.Biometric;

internal partial class BiometricService : IBiometric
{
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    public partial Task<List<BiometricType>> GetEnrolledBiometricTypesAsync();
}