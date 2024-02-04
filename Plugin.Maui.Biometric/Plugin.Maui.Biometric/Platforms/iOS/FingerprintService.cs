using System;
using Foundation;
using LocalAuthentication;

namespace Plugin.Maui.Biometric;

public partial class FingerprintService
{
    public async partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        //var localAuthContext = new LAContext();
        //NSError AuthError;

        //if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthentication, out AuthError))
        //{
        //    if (localAuthContext.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out AuthError))
        //    {
        //        if (localAuthContext.BiometryType == LABiometryType.FaceId)
        //        {
        //            return "FaceId";
        //        }

        //        return "TouchId";
        //    }

        //    return "PassCode";
        //}

        //return "None";

        return BiometricHwStatus.Success;
    }

    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationTokenSource? token = null)
    {
        bool outcome = false;
        var tcs = new TaskCompletionSource<bool>();

        var context = new LAContext();
        if (context.CanEvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, out NSError AuthError))
        {
            var replyHandler = new LAContextReplyHandler((success, error) =>
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    if (success)
                    {
                        outcome = true;
                    }
                    else
                    {
                        outcome = false;
                    }
                    tcs.SetResult(outcome);
                });
            });
            //This will call both TouchID and FaceId 
            context.EvaluatePolicy(LAPolicy.DeviceOwnerAuthenticationWithBiometrics, "Login with touch ID", replyHandler);
        };
        return Task.FromResult(new AuthenticationResponse(
            ));
    }
}