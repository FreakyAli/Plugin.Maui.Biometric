namespace Plugin.Maui.Biometric;

public interface IBiometric
{
    Task<bool> IsDeviceSecureAsync();

    Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationTokenSource? token = null);
}