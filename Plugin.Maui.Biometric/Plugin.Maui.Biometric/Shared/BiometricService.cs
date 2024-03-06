namespace Plugin.Maui.Biometric;

internal partial class BiometricService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);
}

#if NET && !ANDROID && !IOS
internal partial class BiometricService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong)
    {
        throw new NotImplementedException();
    }
}
#endif