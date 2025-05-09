using Foundation;
using LocalAuthentication;

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
                if (localAuthContext.BiometryType != LABiometryType.None)
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
        if (request.AllowPasswordAuth is false)
        {
            context.LocalizedFallbackTitle = string.Empty;
        }
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

    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
    {
        var localAuthContext = new LAContext();
        var availableOptions = new BiometricType[2] { BiometricType.None, BiometricType.None };
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var _))
        {
            var isFace = localAuthContext.BiometryType == LABiometryType.FaceId;
            var isFingerprint = localAuthContext.BiometryType == LABiometryType.TouchId;

            if (isFace || isFingerprint)
            {
                availableOptions[0] = isFace ? BiometricType.Face : BiometricType.None;
                availableOptions[1] = isFingerprint ? BiometricType.Fingerprint : BiometricType.None;
            }
        }
        return Task.FromResult(availableOptions);
    }

    private static partial bool GetIsPlatformSupported() => true;
}
