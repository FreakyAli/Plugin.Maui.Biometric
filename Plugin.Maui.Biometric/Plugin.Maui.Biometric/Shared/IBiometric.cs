namespace Plugin.Maui.Biometric;

public interface IBiometric
{
    Task<bool> IsDeviceSecureAsync();

    Task<BiometricStatus> GetAuthStatusAsync();

    Task<bool> AuthenticateAsync(bool canUseAlternateAuth = true, CancellationTokenSource? token = null);

}