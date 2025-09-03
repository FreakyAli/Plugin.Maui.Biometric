using BiometricPrompt = AndroidX.Biometric.BiometricPrompt;
using Platform = Microsoft.Maui.ApplicationModel.Platform;
using Activity = AndroidX.AppCompat.App.AppCompatActivity;
using BiometricManager = AndroidX.Biometric.BiometricManager;
using Java.Util.Concurrent;
using AndroidX.Core.Content;
using Javax.Crypto;
using Java.Security;

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

    private static SecureAuthenticationResponse? ValidateRequest(SecureAuthenticationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.KeyId))
            return SecureAuthenticationResponse.Failure("Key ID cannot be null or empty");

        if (string.IsNullOrWhiteSpace(request.Transformation))
            return SecureAuthenticationResponse.Failure("Transformation cannot be null or empty");

        if (request.InputData == null || request.InputData.Length == 0)
            return SecureAuthenticationResponse.Failure("Input data cannot be null or empty");

        return null;
    }

    private static IKey GetKeyFromStore(string keyId)
    {
        using var keyStore = KeyStore.GetInstance(AndroidKeyStoreHelpers.KeyStoreName)
            ?? throw new InvalidOperationException("Failed to access Android KeyStore.");

        keyStore.Load(null);

        if (!keyStore.ContainsAlias(keyId))
            throw new InvalidOperationException($"Key with alias '{keyId}' does not exist.");

        return keyStore.GetKey(keyId, null)
            ?? throw new InvalidOperationException($"Key '{keyId}' could not be retrieved from KeyStore.");
    }

    private static Cipher InitCipher(string transformation, CipherMode mode, IKey key)
    {
        var cipher = Cipher.GetInstance(transformation)
            ?? throw new InvalidOperationException("Failed to create cipher.");
        cipher.Init(mode, key);
        return cipher;
    }

    private static (Activity activity, IExecutor executor) GetActivityAndExecutor()
    {
        if (Platform.CurrentActivity is not Activity activity)
            throw new InvalidOperationException(BiometricPromptHelpers.ActivityErrorMsg);

        var activityExecutor = ContextCompat.GetMainExecutor(activity);
        if (activityExecutor is not IExecutor executor)
            throw new InvalidOperationException(BiometricPromptHelpers.ExecutorErrorMsg);

        return (activity, executor);
    }

    private static BiometricPrompt.PromptInfo BuildPromptInfo(SecureAuthenticationRequest request)
    {
        var strength = request.AuthStrength.Equals(AuthenticatorStrength.Strong)
            ? BiometricManager.Authenticators.BiometricStrong
            : BiometricManager.Authenticators.BiometricWeak;

        var builder = new BiometricPrompt.PromptInfo.Builder()
            .SetTitle(request.Title)
            .SetSubtitle(request.Subtitle)
            .SetDescription(request.Description);

        if (request.AllowPasswordAuth)
        {
            builder.SetAllowedAuthenticators(strength | BiometricManager.Authenticators.DeviceCredential);
        }
        else
        {
            builder.SetNegativeButtonText(request.NegativeText);
            builder.SetAllowedAuthenticators(strength);
        }

        return builder.Build();
    }


    internal static async Task<SecureAuthenticationResponse> ProcessCryptoAsync(
    SecureAuthenticationRequest request, CipherMode mode,
    CancellationToken token)
    {
        var validationResult = ValidateRequest(request);
        if (validationResult != null)
            return validationResult;

        try
        {
            using var key = GetKeyFromStore(request.KeyId);
            using var cipher = InitCipher(request.Transformation, mode, key);

            var (activity, executor) = GetActivityAndExecutor();
            var promptInfo = BuildPromptInfo(request);
            var authCallback = new SecureAuthCallback
            {
                Request = request,
                Response = new TaskCompletionSource<SecureAuthenticationResponse>()
            };

            using var biometricPrompt = new BiometricPrompt(activity, executor, authCallback);
            using var cryptoObject = new BiometricPrompt.CryptoObject(cipher);

            using (token.Register(() => biometricPrompt.CancelAuthentication()))
            {
                biometricPrompt.Authenticate(promptInfo, cryptoObject);
                return await authCallback.Response.Task;
            }
        }
        catch (UnrecoverableKeyException)
        {
            return SecureAuthenticationResponse.Failure("Key requires authentication but is not accessible");
        }
        catch (InvalidKeyException ex)
        {
            return SecureAuthenticationResponse.Failure(
                $"Key '{request.KeyId}' is invalid for transformation '{request.Transformation}': {ex.Message}");
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"{mode} failed: {ex.Message}");
        }
    }
}
