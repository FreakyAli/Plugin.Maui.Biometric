using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using AndroidX.Core.Content;
using AndroidX.Biometric;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;
using Android.Content.PM;

namespace Plugin.Maui.Biometric;

internal partial class BiometricService
{
    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        if (Platform.CurrentActivity is not Activity activity)
        {
            return Task.FromResult(BiometricHwStatus.Failure);
        }

        var biometricManager = BiometricManager.From(activity);
        var strength = authStrength.Equals(AuthenticatorStrength.Strong) ?
            BiometricManager.Authenticators.BiometricStrong :
            BiometricManager.Authenticators.BiometricWeak;

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

    public partial async Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        try
        {
            if (Platform.CurrentActivity is not Activity activity)
            {
                //This case should be logically unreachable but adding this just
                //In case for some reason Platform's CurrentActivity decides to flip with me.
                return new AuthenticationResponse
                {
                    Status = BiometricResponseStatus.Failure,
                    ErrorMsg = "Your Platform.CurrentActivity either returned null or is not of type `AndroidX.AppCompat.App.AppCompatActivity`, ensure your Activity is of the right type and that its not null when you call this method"
                };
            }

            var strength = request.AuthStrength.Equals(AuthenticatorStrength.Strong) ?
               BiometricManager.Authenticators.BiometricStrong :
               BiometricManager.Authenticators.BiometricWeak;

            var allInfo = new BiometricPrompt.PromptInfo.Builder()
                    .SetTitle(request.Title)
                    .SetSubtitle(request.Subtitle)
                    .SetDescription(request.Description);

            if (request.AllowPasswordAuth)
            {
                allInfo.SetAllowedAuthenticators(strength | BiometricManager.Authenticators.DeviceCredential);
            }
            else
            {
                allInfo.SetNegativeButtonText(request.NegativeText);
                allInfo.SetAllowedAuthenticators(strength);
            }

            var promptInfo = allInfo.Build();
            var executor = ContextCompat.GetMainExecutor(activity);
            var authCallback = new AuthCallback()
            {
                Response = new TaskCompletionSource<AuthenticationResponse>()
            };

            var biometricPrompt = new BiometricPrompt(activity, executor, authCallback);

            await using (token.Register(() => biometricPrompt.CancelAuthentication()))
            {
                biometricPrompt.Authenticate(promptInfo);
                var response = await authCallback.Response.Task;
                return response;
            }
        }
        catch (Exception ex)
        {
            return new AuthenticationResponse
            {
                Status = BiometricResponseStatus.Failure,
                ErrorMsg = ex.Message + ex.StackTrace
            };
        }
    }

    public partial Task<List<BiometricType>> GetEnrolledBiometricTypesAsync()
    {
        var availableOptions = new List<BiometricType>();
        if (Platform.CurrentActivity is Activity activity)
        {
            var biometricManager = BiometricManager.From(activity);
            var canAuthenticate = biometricManager.CanAuthenticate(BiometricManager.Authenticators.BiometricWeak);
            if (canAuthenticate == BiometricManager.BiometricSuccess)
            {
                // Determine the type of biometric hardware available
                var packageManager = activity.PackageManager;
                var isFingerprint = packageManager.HasSystemFeature(PackageManager.FeatureFingerprint);
                var isFace = OperatingSystem.IsAndroidVersionAtLeast(29) && packageManager.HasSystemFeature(PackageManager.FeatureFace);

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
        }
        return Task.FromResult(availableOptions);
    }
  
    private static partial bool GetIsPlatformSupported() => true;
}