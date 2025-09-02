using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Java.Lang;

namespace Plugin.Maui.Biometric;

internal sealed class SecureAuthCallback : BiometricPrompt.AuthenticationCallback
{
    public required TaskCompletionSource<SecureAuthenticationResponse> Response { get; set; }

    public required SecureAuthenticationRequest Request { get; set; }

    public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
    {
        base.OnAuthenticationSucceeded(result);
        try
        {
            var cipherData = result?.CryptoObject?.Cipher?.DoFinal(Request.InputData);
            if (cipherData is null || cipherData.Length == 0)
            {
                Response.TrySetResult(SecureAuthenticationResponse.Failure("Failed to retrieve cipher data after successful authentication."));
                return;
            }
            var response = SecureAuthenticationResponse.Success(cipherData);
            Response.TrySetResult(response);
        }
        catch (System.Exception ex)
        {
            Response.TrySetResult(SecureAuthenticationResponse.Failure($"Operation failed: {ex.Message}"));
            return;
        }
    }

    public override void OnAuthenticationError(int errorCode, ICharSequence errString)
    {
        base.OnAuthenticationError(errorCode, errString);
        Response.TrySetResult(SecureAuthenticationResponse.Failure($"Authentication failed, please try again later, error code:{errorCode} {errString}"));
    }

    public override void OnAuthenticationFailed()
    {
        base.OnAuthenticationFailed();
        Response.TrySetResult(SecureAuthenticationResponse.Failure("Biometric not recognized, try again"));
    }
}