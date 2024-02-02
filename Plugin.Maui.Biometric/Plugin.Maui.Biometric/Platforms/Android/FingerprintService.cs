using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using AndroidX.Core.Content;
using Java.Lang;
using AndroidX.Biometric;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;

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

public partial class FingerprintService
{
    private Activity CurrentActivity => (Activity)Platform.CurrentActivity;

    public async partial Task<BiometricStatus> GetAuthStatusAsync()
    {
        return BiometricStatus.Success;
    }


    private void ShowBiometricPrompt()
    {
        var biometricManager = BiometricManager.From(CurrentActivity);

        var value = biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong);
        switch (value)
        {
            case BiometricManager.BiometricSuccess:
                break;
            case BiometricManager.BiometricErrorNoHardware:
                break;
            case BiometricManager.BiometricErrorHwUnavailable:
                break;
            case BiometricManager.BiometricErrorNoneEnrolled:
                break;
        }

        var executor = ContextCompat.GetMainExecutor(CurrentActivity);

        var biometricPrompt = new BiometricPrompt(CurrentActivity, executor, new AuthCallback());



        var promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .SetTitle("Biometric login for my app")
                .SetSubtitle("Log in using your biometric credential")
                .SetAllowedAuthenticators(
                    BiometricManager.Authenticators.BiometricStrong |
                    BiometricManager.Authenticators.DeviceCredential)
                .Build();
    }

    public async partial Task<bool> IsDeviceSecureAsync()
    {
        return true;
    }

    public async partial Task<bool> AuthenticateAsync(
        bool canUseAlternateAuth = true,
        CancellationTokenSource? token = null)
    {
        return true;
    }

}

