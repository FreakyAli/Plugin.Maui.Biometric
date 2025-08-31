using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using AndroidX.Core.Content;
using AndroidX.Biometric;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;
using Java.Util.Concurrent;

namespace Plugin.Maui.Biometric;

internal static class BiometricPromptHelpers
{
    internal const string ActivityErrorMsg = """
    Your Platform.CurrentActivity either returned null 
    or is not of type `AndroidX.AppCompat.App.AppCompatActivity`, 
    ensure your Activity is of the right type and that 
    its not null when you call this method
    """;

    internal const string ExecutorErrorMsg = """
    Your Platform.CurrentActivity's main executor could not be obtained, 
    ensure your Activity is of the right type and that 
    its not null when you call this method
    """;

    public static async Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
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
                    ErrorMsg = ActivityErrorMsg
                };
            }
            var activityExecutor = ContextCompat.GetMainExecutor(activity);
            if (activityExecutor is not IExecutor executor)
            {
                // Executor creation fails
                return new AuthenticationResponse
                {
                    Status = BiometricResponseStatus.Failure,
                    ErrorMsg = ExecutorErrorMsg
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
            var authCallback = new AuthCallback()
            {
                Response = new TaskCompletionSource<AuthenticationResponse>()
            };

            var biometricPrompt = new BiometricPrompt(activity, executor, authCallback);

            using (token.Register(() => biometricPrompt.CancelAuthentication()))
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
}
