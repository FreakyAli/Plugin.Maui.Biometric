using System;

namespace Plugin.Maui.Biometric;

public partial class FingerprintService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationTokenSource? token = null);
   
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength = AuthenticatorStrength.Strong);

    public partial Task<bool> IsDeviceSecureAsync();
}
