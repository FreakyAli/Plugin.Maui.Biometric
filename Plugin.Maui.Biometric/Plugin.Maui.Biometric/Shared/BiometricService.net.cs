﻿using Plugin.Maui.Biometric.Shared;

namespace Plugin.Maui.Biometric;
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

    public partial Task<BiometricType> GetBiometricTypeAsync()
    {
        throw new NotImplementedException();
    }
}
#endif