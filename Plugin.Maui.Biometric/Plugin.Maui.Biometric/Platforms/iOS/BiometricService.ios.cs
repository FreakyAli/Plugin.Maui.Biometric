using Foundation;
using LocalAuthentication;
using Plugin.Maui.Biometric.Shared;

namespace Plugin.Maui.Biometric;

internal partial class BiometricService
{
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        var localAuthContext = new LAContext();
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out var _))
        {
            if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var _))
            {
                if (localAuthContext.BiometryType == LABiometryType.FaceId)
                {
                    return Task.FromResult(BiometricHwStatus.Success);
                }

                return Task.FromResult(BiometricHwStatus.NotEnrolled);
            }

            return Task.FromResult(BiometricHwStatus.Unavailable);
        }

        return Task.FromResult(BiometricHwStatus.Failure);
    }

    public async partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        var response = new AuthenticationResponse();
        var context = new LAContext();
        LAPolicy policy = request.AllowPasswordAuth ? LAPolicy.DeviceOwnerAuthentication : LAPolicy.DeviceOwnerAuthenticationWithBiometrics;
        if (context.CanEvaluatePolicy(policy, out NSError _))
        {
            var callback = await context.EvaluatePolicyAsync(policy, request.Title);
            response.Status = callback.Item1 ? BiometricResponseStatus.Success : BiometricResponseStatus.Failure;
            response.AuthenticationType = AuthenticationType.Unknown;
            response.ErrorMsg = callback.Item2?.ToString();
        };
        return response;
    }

    public partial Task<BiometricType> GetBiometricTypeAsync()
    {
        var localAuthContext = new LAContext();
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var _))
        {
            return Task.FromResult(localAuthContext.BiometryType switch
            {
                LABiometryType.FaceId => BiometricType.Face,
                LABiometryType.TouchId => BiometricType.Fingerprint,
                _ => BiometricType.None
            });
        }
        return Task.FromResult(BiometricType.None);
    }
}