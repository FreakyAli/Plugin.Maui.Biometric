using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Java.Lang;
using System.Diagnostics;

namespace Plugin.Maui.Biometric;

internal sealed class AuthCallback : BiometricPrompt.AuthenticationCallback
{
    public required TaskCompletionSource<AuthenticationResponse> Response { get; set; }

    public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
    {
        base.OnAuthenticationSucceeded(result);
        var authType = result.AuthenticationType switch
        {
            BiometricPrompt.AuthenticationResultTypeBiometric => AuthenticationType.Biometric,
            BiometricPrompt.AuthenticationResultTypeDeviceCredential => AuthenticationType.DeviceCreds,
            _ => AuthenticationType.Unknown,
        };
        Response.TrySetResult(new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Success,
            AuthenticationType = authType,
            ErrorMsg = string.Empty
        });
    }

    public override void OnAuthenticationError(int errorCode, ICharSequence errString)
    {
        base.OnAuthenticationError(errorCode, errString);
        Response.TrySetResult(new AuthenticationResponse
        {
            Status = BiometricResponseStatus.Failure,
            ErrorMsg = $"Authentication failed, please try again later, error code:{errorCode} {errString}"
        });
    }

    public override void OnAuthenticationFailed()
    {
        base.OnAuthenticationFailed();
        Debug.WriteLine(typeof(AuthCallback).Name + " OnAuthenticationFailed");
        Debug.WriteLine("Biometric not recognized, try again");
    }
}