using LocalAuthentication;

namespace Plugin.Maui.Biometric;

internal class LAContextHelpers
{
    internal static (BiometricHwStatus status, string? errorMessage) GetBiometricHwStatus()
    {
        using var localAuthContext = new LAContext();
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out var ownerError))
        {
            if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var authError))
            {
                if (localAuthContext.BiometryType != LABiometryType.None)
                {
                    return (BiometricHwStatus.Success, null);
                }

                return (BiometricHwStatus.NotEnrolled, authError?.GetErrorMessage());
            }

            return (BiometricHwStatus.Unavailable, ownerError.GetErrorMessage());
        }

        return (BiometricHwStatus.Failure, "Biometric authentication failed.");
    }
}
