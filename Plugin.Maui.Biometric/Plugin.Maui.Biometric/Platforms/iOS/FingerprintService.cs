using System;
namespace Plugin.Maui.Biometric;

public partial class FingerprintService 
{
    public async partial Task<BiometricStatus> GetAuthStatusAsync()
    {

        return BiometricStatus.Success;
    }

    public async partial Task<bool> IsDeviceSecureAsync()
    {
        return true;
    }

    public async partial Task<bool> AuthenticateAsync(bool canUseAlternateAuth = true, CancellationTokenSource? token = null)
    {
        return true;
    }
}