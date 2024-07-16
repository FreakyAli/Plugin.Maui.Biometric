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

    public partial Task<List<BiometricType>> GetEnrolledBiometricTypesAsync()
    {
        var localAuthContext = new LAContext();
        var availableOptions = new List<BiometricType>();
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var _))
        {
            var isFace = localAuthContext.BiometryType == LABiometryType.FaceId;
            var isFingerprint = localAuthContext.BiometryType == LABiometryType.TouchId;
            if (isFace)
            {
                availableOptions.Add(BiometricType.Face);
            }
            if (isFingerprint)
            {
                availableOptions.Add(BiometricType.Fingerprint);
            }
            if (!isFace && !isFingerprint)
            {
                availableOptions.Add(BiometricType.None);
            }
        }
        return Task.FromResult(availableOptions);
    }

    private static partial bool GetIsPlatformSupported() => true;
}
