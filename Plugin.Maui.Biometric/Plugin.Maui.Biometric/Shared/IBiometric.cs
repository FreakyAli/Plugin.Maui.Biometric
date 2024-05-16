using Plugin.Maui.Biometric.Shared;

namespace Plugin.Maui.Biometric;

public interface IBiometric
{
    Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);
    Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token);
    Task<BiometricType> GetBiometricTypeAsync();
}