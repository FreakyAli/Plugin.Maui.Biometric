using Foundation;
using LocalAuthentication;

namespace Plugin.Maui.Biometric;

internal partial class BiometricService
{
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        var localAuthContext = new LAContext();
        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out var error))
        {
            if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out var authError))
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

    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        var response = new AuthenticationResponse();
        var context = new LAContext();
        if (context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out NSError AuthError))
        {
            var replyHandler = new LAContextReplyHandler((success, error) =>
            {
                response.Status = success ? BiometricResponseStatus.Success : BiometricResponseStatus.Failure;
                response.AuthenticationType = AuthenticationType.Unknown;
                response.ErrorMsg = error.ToString();
            });
            //This will call both TouchID and FaceId 
            context.EvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, request.Title, replyHandler);
        };
        return Task.FromResult(response);
    }
}