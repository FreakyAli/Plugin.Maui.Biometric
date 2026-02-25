using Foundation;
using LocalAuthentication;

namespace Plugin.Maui.Biometric;

internal partial class BiometricService
{
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    { 
        var (status, _) = LAContextHelpers.GetBiometricHwStatus();
        return Task.FromResult(status);
    }

    public async partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        var response = new AuthenticationResponse();
        using var context = new LAContext();

        if (request.AllowPasswordAuth is false)
        {
            context.LocalizedFallbackTitle = string.Empty;
        }

        LAPolicy policy = request.AllowPasswordAuth
            ? LAPolicy.DeviceOwnerAuthentication
            : LAPolicy.DeviceOwnerAuthenticationWithBiometrics;

        if (context.CanEvaluatePolicy(policy, out NSError _))
        {
            // Register cancellation to invalidate the context
            try
            {
                using (token.Register(() => context.Invalidate()))
                {
                    var callback = await context.EvaluatePolicyAsync(policy, request.Title);
                    response.Status = callback.Item1
                        ? BiometricResponseStatus.Success
                        : BiometricResponseStatus.Failure;
                    response.AuthenticationType = AuthenticationType.Unknown;
                    response.ErrorMsg = callback.Item2?.ToString();
                }
            }
            catch (OperationCanceledException)
            {
                response.Status = BiometricResponseStatus.Failure;
                response.ErrorMsg = "Authentication was cancelled.";
            }
        }
        else
        {
            response.Status = BiometricResponseStatus.Failure;
            response.ErrorMsg = "Biometric authentication not available.";
        }

        return response;
    }


    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
    {
        using var localAuthContext = new LAContext();
        var biometricTypes = new List<BiometricType>();

        if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out _))
        {
            switch (localAuthContext.BiometryType)
            {
                case LABiometryType.FaceId:
                    biometricTypes.Add(BiometricType.Face);
                    break;
                case LABiometryType.TouchId:
                    biometricTypes.Add(BiometricType.Fingerprint);
                    break;
                case LABiometryType.None:
                default:
                    biometricTypes.Add(BiometricType.None);
                    break;
            }
        }
        return Task.FromResult(biometricTypes.ToArray());
    }

    private static partial bool GetIsPlatformSupported() => true;
}
