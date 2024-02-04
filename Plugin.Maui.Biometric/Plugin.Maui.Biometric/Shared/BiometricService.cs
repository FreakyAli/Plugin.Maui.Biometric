namespace Plugin.Maui.Biometric;

internal partial class BiometricService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);
}

public class BiometricAuthenticationService
{
    private static readonly Lazy<IBiometric> defaultImpl =
        new(()=>new BiometricService(), LazyThreadSafetyMode.PublicationOnly);

    public static IBiometric Default
    {
        get => defaultImpl.Value;
    }
}