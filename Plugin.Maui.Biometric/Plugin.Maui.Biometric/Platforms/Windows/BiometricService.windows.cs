using System;
using System.Threading;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;

namespace Plugin.Maui.Biometric;
internal partial class BiometricService
{
    public partial async Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        return availability switch
        {
            UserConsentVerifierAvailability.Available => BiometricHwStatus.Success,
            UserConsentVerifierAvailability.DeviceBusy => BiometricHwStatus.Unavailable,
            UserConsentVerifierAvailability.DeviceNotPresent => BiometricHwStatus.NoHardware,
            UserConsentVerifierAvailability.DisabledByPolicy => BiometricHwStatus.Unsupported,
            UserConsentVerifierAvailability.NotConfiguredForUser => BiometricHwStatus.NotEnrolled,
            _ => BiometricHwStatus.Failure,
        };
    }

    public partial async Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        try
        {
            var availability = await UserConsentVerifier.CheckAvailabilityAsync();
            if (availability == UserConsentVerifierAvailability.Available)
            {
                var authStatus = await UserConsentVerifier.RequestVerificationAsync(request.Description);
                if (authStatus == UserConsentVerificationResult.Verified)
                {
                    return new AuthenticationResponse
                    {
                        Status = BiometricResponseStatus.Success,
                        AuthenticationType = AuthenticationType.WindowsHello,
                        ErrorMsg = null
                    };
                }

                return new AuthenticationResponse
                {
                    Status = BiometricResponseStatus.Failure,
                    AuthenticationType = AuthenticationType.WindowsHello,
                    ErrorMsg = $"User did not verify, authentication status: {authStatus}"
                };
            }

            return new AuthenticationResponse
            {
                Status = BiometricResponseStatus.Failure,
                AuthenticationType = AuthenticationType.WindowsHello,
                ErrorMsg = "Biometric authentication is not available on this device."
            };
        }
        catch (Exception ex)
        {
            return new AuthenticationResponse
            {
                Status = BiometricResponseStatus.Failure,
                AuthenticationType = AuthenticationType.WindowsHello,
                ErrorMsg = ex.Message + ex.StackTrace
            };
        }
    }

    public partial async Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
    {
        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability == UserConsentVerifierAvailability.Available)
            return [BiometricType.WindowsHello];
        return [BiometricType.None];
    }

    private static partial bool GetIsPlatformSupported() => true;
    
    public void Dispose()
    {
    }
}