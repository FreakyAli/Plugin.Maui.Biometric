using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Java.Lang;

namespace Plugin.Maui.Biometric;

public class AuthCallback : BiometricPrompt.AuthenticationCallback
{
    public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
    {
        base.OnAuthenticationSucceeded(result);
    }

    public override void OnAuthenticationFailed()
    {
        base.OnAuthenticationFailed();
    }

    public override void OnAuthenticationError(int errorCode, ICharSequence errString)
    {
        base.OnAuthenticationError(errorCode, errString);
    }
}

