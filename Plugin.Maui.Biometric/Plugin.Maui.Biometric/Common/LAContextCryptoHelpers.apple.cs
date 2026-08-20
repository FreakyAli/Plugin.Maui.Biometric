using Foundation;
using LocalAuthentication;
using Security;
using System.Security.Cryptography;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Orchestrates biometric-gated cryptographic operations on iOS/macOS.
/// Mirrors <c>BiometricPromptHelpers</c> on Android.
/// </summary>
internal static class LAContextCryptoHelpers
{
    // ─── Shared Validation ───────────────────────────────────────────────────

    private static SecureAuthenticationResponse? ValidateRequest(SecureAuthenticationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.KeyId))
            return SecureAuthenticationResponse.Failure("Key ID cannot be null or empty.");

        if (request.InputData is null || request.InputData.Length == 0)
            return SecureAuthenticationResponse.Failure("Input data cannot be null or empty.");

        return null;
    }

    private static SecureAuthenticationResponse? ValidateAesRequest(SecureAuthenticationRequest request)
    {
        var baseValidation = ValidateRequest(request);
        if (baseValidation is not null) return baseValidation;

        if (request.Algorithm != KeyAlgorithm.Aes)
            return SecureAuthenticationResponse.Failure("Only AES algorithm is supported for symmetric encryption.");

        if (request.BlockMode != BlockMode.Gcm)
            return SecureAuthenticationResponse.Failure("Only GCM block mode is supported. Set BlockMode to Gcm.");

        if (request.Padding != Padding.None)
            return SecureAuthenticationResponse.Failure("GCM mode requires Padding to be None.");

        return null;
    }

    // ─── Biometric Authentication ─────────────────────────────────────────────

    /// <summary>
    /// Presents the biometric prompt and returns an authenticated <see cref="LAContext"/>
    /// on success.  The caller is responsible for disposing the context.
    /// </summary>
    private static async Task<(LAContext? context, string? error)> AuthenticateAsync(
        string localizedReason, bool allowPasswordFallback, CancellationToken token)
    {
        var context = new LAContext();

        if (!allowPasswordFallback)
            context.LocalizedFallbackTitle = string.Empty;

        var policy = allowPasswordFallback
            ? LAPolicy.DeviceOwnerAuthentication
            : LAPolicy.DeviceOwnerAuthenticationWithBiometrics;

        if (!context.CanEvaluatePolicy(policy, out NSError _))
        {
            context.Dispose();
            return (null, "Biometric authentication is not available on this device.");
        }

        try
        {
            using (token.Register(() => context.Invalidate()))
            {
                var (success, nsError) = await context.EvaluatePolicyAsync(policy, localizedReason);
                if (!success)
                {
                    context.Dispose();
                    // Check cancellation first — a cancelled token produces a generic LAError
                    if (token.IsCancellationRequested)
                        return (null, "Authentication was cancelled.");
                    return (null, nsError?.ToString() ?? "Authentication failed.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            context.Dispose();
            return (null, "Authentication was cancelled.");
        }
        catch (Exception ex)
        {
            context.Dispose();
            return (null, $"Authentication error: {ex.GetFullMessage()}");
        }

        return (context, null);
    }

    // ─── AES-GCM (symmetric) ─────────────────────────────────────────────────

    internal static async Task<SecureAuthenticationResponse> ProcessAesCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
    {
        var validation = ValidateAesRequest(request);
        if (validation is not null) return validation;

        var (context, authError) = await AuthenticateAsync(
            request.Title, request.AllowPasswordAuth, token);
        if (context is null)
            return SecureAuthenticationResponse.Failure(authError!);

        byte[]? keyBytes = null;
        try
        {
            var (retrievedKey, keyError) = AppleKeychainHelpers.RetrieveSymmetricKey(request.KeyId, context);
            if (retrievedKey is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            keyBytes = retrievedKey;

            return encrypt
                ? AesGcmHelpers.Encrypt(keyBytes, request.InputData)
                : AesGcmHelpers.Decrypt(keyBytes, request.InputData, request.IV);
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure(
                $"{(encrypt ? "Encrypt" : "Decrypt")} failed: {ex.GetFullMessage()}");
        }
        finally
        {
            if (keyBytes is not null)
                Array.Clear(keyBytes, 0, keyBytes.Length);
            context.Dispose();
        }
    }

    // ─── RSA (asymmetric encrypt / decrypt) ───────────────────────────────────

    internal static async Task<SecureAuthenticationResponse> ProcessRsaCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
    {
        var validation = ValidateRequest(request);
        if (validation is not null) return validation;

        var algorithm = AppleKeychainHelpers.MapEncryptAlgorithm(request.Padding);

        return encrypt
            ? EncryptRsa(request, algorithm)
            : await DecryptRsaAsync(request, algorithm, token);
    }

    private static SecureAuthenticationResponse EncryptRsa(
        SecureAuthenticationRequest request, SecKeyAlgorithm algorithm)
    {
        try
        {
            var (publicKey, pubError) = AppleKeychainHelpers.RetrieveAsymmetricPublicKey(request.KeyId);
            if (publicKey is null)
                return SecureAuthenticationResponse.Failure(pubError!);

            using (publicKey)
            {
                var ciphertext = publicKey.CreateEncryptedData(
                    algorithm, NSData.FromArray(request.InputData), out NSError? encError);

                return ciphertext is null
                    ? SecureAuthenticationResponse.Failure($"RSA encrypt failed: {encError?.GetErrorMessage()}")
                    : SecureAuthenticationResponse.Success(ciphertext.ToArray());
            }
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"RSA encrypt failed: {ex.GetFullMessage()}");
        }
    }

    private static async Task<SecureAuthenticationResponse> DecryptRsaAsync(
        SecureAuthenticationRequest request, SecKeyAlgorithm algorithm, CancellationToken token)
    {
        var (context, authError) = await AuthenticateAsync(
            request.Title, request.AllowPasswordAuth, token);
        if (context is null)
            return SecureAuthenticationResponse.Failure(authError!);

        try
        {
            var (privateKey, privError) = AppleKeychainHelpers.RetrieveAsymmetricPrivateKey(request.KeyId, context);
            if (privateKey is null)
                return SecureAuthenticationResponse.Failure(privError!);

            using (privateKey)
            {
                var plaintext = privateKey.CreateDecryptedData(
                    algorithm, NSData.FromArray(request.InputData), out NSError? decError);

                return plaintext is null
                    ? SecureAuthenticationResponse.Failure($"RSA decrypt failed: {decError?.GetErrorMessage()}")
                    : SecureAuthenticationResponse.Success(plaintext.ToArray());
            }
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"RSA decrypt failed: {ex.GetFullMessage()}");
        }
        finally
        {
            context.Dispose();
        }
    }

    // ─── Sign (EC Secure Enclave or RSA) ──────────────────────────────────────

    internal static async Task<SecureAuthenticationResponse> ProcessSignAsync(
        string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest,
        string localizedReason, bool allowPasswordFallback, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return SecureAuthenticationResponse.Failure("KeyId cannot be null or empty.");

        if (inputData is null || inputData.Length == 0)
            return SecureAuthenticationResponse.Failure("Input data cannot be null or empty.");

        var (context, authError) = await AuthenticateAsync(localizedReason, allowPasswordFallback, token);
        if (context is null)
            return SecureAuthenticationResponse.Failure(authError!);

        try
        {
            var (privateKey, keyError) = AppleKeychainHelpers.RetrieveAsymmetricPrivateKey(keyId, context);
            if (privateKey is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            using (privateKey)
            {
                var sigAlgorithm = AppleKeychainHelpers.MapSignatureAlgorithm(algorithm, digest);
                var signature    = privateKey.CreateSignature(
                    sigAlgorithm, NSData.FromArray(inputData), out NSError? sigError);

                return signature is null
                    ? SecureAuthenticationResponse.Failure($"Signing failed: {sigError?.GetErrorMessage()}")
                    : SecureAuthenticationResponse.Success(signature.ToArray());
            }
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"Sign failed: {ex.GetFullMessage()}");
        }
        finally
        {
            context.Dispose();
        }
    }

    // ─── Verify (EC or RSA) ────────────────────────────────────────────────────

    internal static Task<SecureAuthenticationResponse> ProcessVerifyAsync(
        string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest)
    {
        if (string.IsNullOrWhiteSpace(keyId))
            return Task.FromResult(SecureAuthenticationResponse.Failure("KeyId cannot be null or empty."));

        if (inputData is null || inputData.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Input data cannot be null or empty."));

        if (signature is null || signature.Length == 0)
            return Task.FromResult(SecureAuthenticationResponse.Failure("Signature cannot be null or empty."));

        try
        {
            var (publicKey, keyError) = AppleKeychainHelpers.RetrieveAsymmetricPublicKey(keyId);
            if (publicKey is null)
                return Task.FromResult(SecureAuthenticationResponse.Failure(keyError!));

            using (publicKey)
            {
                var sigAlgorithm = AppleKeychainHelpers.MapSignatureAlgorithm(algorithm, digest);
                bool valid = publicKey.VerifySignature(
                    sigAlgorithm,
                    NSData.FromArray(inputData),
                    NSData.FromArray(signature),
                    out NSError? verifyError);

                return Task.FromResult(valid
                    ? SecureAuthenticationResponse.Success(Array.Empty<byte>())
                    : SecureAuthenticationResponse.Failure(
                        $"Signature verification failed: {verifyError?.GetErrorMessage()}"));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(
                SecureAuthenticationResponse.Failure($"Verify failed: {ex.GetFullMessage()}"));
        }
    }
}
