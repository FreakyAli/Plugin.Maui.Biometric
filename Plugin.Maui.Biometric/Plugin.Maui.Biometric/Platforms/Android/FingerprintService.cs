using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using AndroidX.Core.Content;
using AndroidX.Biometric;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;

namespace Plugin.Maui.Biometric;

public partial class FingerprintService
{
    private Activity CurrentActivity => (Activity)Platform.CurrentActivity;

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        var biometricManager = BiometricManager.From(CurrentActivity);

        var strength = authStrength.Equals(AuthenticatorStrength.Strong) ?
            BiometricManager.Authenticators.BiometricStrong :
            BiometricManager.Authenticators.BiometricStrong;

        var value = biometricManager.CanAuthenticate(strength);
        var response = value switch
        {
            BiometricManager.BiometricSuccess => BiometricHwStatus.Success,
            BiometricManager.BiometricErrorNoHardware => BiometricHwStatus.NoHardware,
            BiometricManager.BiometricErrorHwUnavailable => BiometricHwStatus.Unavailable,
            BiometricManager.BiometricErrorNoneEnrolled => BiometricHwStatus.NotEnrolled,
            BiometricManager.BiometricErrorUnsupported => BiometricHwStatus.Unsupported,
            _ => BiometricHwStatus.Failure,
        };

        return Task.FromResult(response);
    }


    private void ShowBiometricPrompt()
    {



    }

    public async partial Task<bool> IsDeviceSecureAsync()
    {
        return true;
    }

    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationTokenSource? token = null)
    {
        var executor = ContextCompat.GetMainExecutor(CurrentActivity);

        var biometricPrompt = new BiometricPrompt(CurrentActivity, executor, new AuthCallback());



        var promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .SetTitle("Biometric login for my app")
                .SetSubtitle("Log in using your biometric credential")
                .SetAllowedAuthenticators(
                    BiometricManager.Authenticators.BiometricStrong |
                    BiometricManager.Authenticators.DeviceCredential)
                .Build();


        var response = new AuthenticationResponse()
        {

        };
        return Task.FromResult(response);
    }

}

