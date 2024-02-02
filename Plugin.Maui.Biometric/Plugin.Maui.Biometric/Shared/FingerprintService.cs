using System;

namespace Plugin.Maui.Biometric;

public partial class FingerprintService : IBiometric
{
    public partial Task<bool> AuthenticateAsync(bool canUseAlternateAuth = true, CancellationTokenSource? token = null);
   
    public partial Task<BiometricStatus> GetAuthStatusAsync();

    public partial Task<bool> IsDeviceSecureAsync();
}
