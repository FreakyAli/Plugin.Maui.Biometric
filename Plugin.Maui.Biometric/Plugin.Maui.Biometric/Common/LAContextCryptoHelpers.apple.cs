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

    // ─── Biometric Authentication ─────────────────────────────────────────────

    /// <summary>
    /// Presents the biometric prompt and returns an authenticated <see cref="LAContext"/>
    /// on success.  The caller is responsible for disposing the context.
    /// Mirrors <c>GetActivityAndExecutor</c> + prompt setup in <c>BiometricPromptHelpers</c>.
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
                    return (null, nsError?.ToString() ?? "Authentication failed.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            context.Dispose();
            return (null, "Authentication was cancelled.");
        }

        return (context, null);
    }

    // ─── AES-GCM (symmetric) ─────────────────────────────────────────────────

    /// <summary>
    /// Encrypts or decrypts data with the AES key stored in the Keychain.
    /// <para>
    /// Encrypt output format:  <c>OutputData</c> = ciphertext ‖ 16-byte GCM tag,
    /// <c>IV</c> = 12-byte nonce.  This matches the GCM output format produced by
    /// Android's <c>Cipher.doFinal</c>, so payloads are cross-platform compatible.
    /// </para>
    /// </summary>
    internal static async Task<SecureAuthenticationResponse> ProcessAesCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
    {
        var validation = ValidateRequest(request);
        if (validation is not null) return validation;

        var (context, authError) = await AuthenticateAsync(
            request.Title, request.AllowPasswordAuth, token);
        if (context is null)
            return SecureAuthenticationResponse.Failure(authError!);

        try
        {
            var (keyBytes, keyError) = AppleKeychainHelpers.RetrieveSymmetricKey(request.KeyId, context);
            if (keyBytes is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            if (encrypt)
            {
                var iv         = RandomNumberGenerator.GetBytes(12);  // 96-bit nonce
                var ciphertext = new byte[request.InputData.Length];
                var tag        = new byte[16];                         // 128-bit auth tag

                using var aesGcm = new AesGcm(keyBytes, 16);
                aesGcm.Encrypt(iv, request.InputData, ciphertext, tag);

                // Append tag to ciphertext — matches Android Cipher GCM output layout.
                var outputData = new byte[ciphertext.Length + tag.Length];
                ciphertext.CopyTo(outputData, 0);
                tag.CopyTo(outputData, ciphertext.Length);

                return SecureAuthenticationResponse.Success(outputData, iv);
            }
            else
            {
                if (request.IV is null || request.IV.Length == 0)
                    return SecureAuthenticationResponse.Failure("IV is required for AES-GCM decryption.");

                if (request.InputData.Length < 16)
                    return SecureAuthenticationResponse.Failure("Input data is too short for AES-GCM decryption.");

                // Split ciphertext and 16-byte tag
                var ciphertext = request.InputData[..^16];
                var tag        = request.InputData[^16..];
                var plaintext  = new byte[ciphertext.Length];

                using var aesGcm = new AesGcm(keyBytes, 16);
                aesGcm.Decrypt(request.IV, ciphertext, tag, plaintext);

                return SecureAuthenticationResponse.Success(plaintext);
            }
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure(
                $"{(encrypt ? "Encrypt" : "Decrypt")} failed: {ex.GetFullMessage()}");
        }
        finally
        {
            context.Dispose();
        }
    }

    // ─── RSA (asymmetric encrypt / decrypt) ───────────────────────────────────

    /// <summary>
    /// Encrypts with the RSA public key (no biometric needed) or decrypts with
    /// the biometric-protected private key.
    /// </summary>
    internal static async Task<SecureAuthenticationResponse> ProcessRsaCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
    {
        var validation = ValidateRequest(request);
        if (validation is not null) return validation;

        var algorithm = AppleKeychainHelpers.MapEncryptAlgorithm(request.Padding);

        try
        {
            if (encrypt)
            {
                // Public key encryption — no biometric required.
                var (publicKey, pubError) = AppleKeychainHelpers.RetrieveAsymmetricPublicKey(request.KeyId);
                if (publicKey is null)
                    return SecureAuthenticationResponse.Failure(pubError!);

                var ciphertext = publicKey.CreateEncryptedData(
                    algorithm, NSData.FromArray(request.InputData), out NSError? encError);

                return ciphertext is null
                    ? SecureAuthenticationResponse.Failure($"RSA encrypt failed: {encError?.GetErrorMessage()}")
                    : SecureAuthenticationResponse.Success(ciphertext.ToArray());
            }
            else
            {
                // Private key decryption — biometric required.
                var (context, authError) = await AuthenticateAsync(
                    request.Title, request.AllowPasswordAuth, token);
                if (context is null)
                    return SecureAuthenticationResponse.Failure(authError!);

                try
                {
                    var (privateKey, privError) = AppleKeychainHelpers.RetrieveAsymmetricPrivateKey(request.KeyId, context);
                    if (privateKey is null)
                        return SecureAuthenticationResponse.Failure(privError!);

                    var plaintext = privateKey.CreateDecryptedData(
                        algorithm, NSData.FromArray(request.InputData), out NSError? decError);

                    return plaintext is null
                        ? SecureAuthenticationResponse.Failure($"RSA decrypt failed: {decError?.GetErrorMessage()}")
                        : SecureAuthenticationResponse.Success(plaintext.ToArray());
                }
                finally
                {
                    context.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure(
                $"RSA {(encrypt ? "encrypt" : "decrypt")} failed: {ex.GetFullMessage()}");
        }
    }

    // ─── Sign (EC Secure Enclave or RSA) ──────────────────────────────────────

    /// <summary>
    /// Signs <paramref name="inputData"/> with the private key stored under
    /// <paramref name="keyId"/>.  Biometric authentication is required to access
    /// the private key.
    /// </summary>
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

            var sigAlgorithm = AppleKeychainHelpers.MapSignatureAlgorithm(algorithm, digest);
            var signature    = privateKey.CreateSignature(
                sigAlgorithm, NSData.FromArray(inputData), out NSError? sigError);

            return signature is null
                ? SecureAuthenticationResponse.Failure($"Signing failed: {sigError?.GetErrorMessage()}")
                : SecureAuthenticationResponse.Success(signature.ToArray());
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

    /// <summary>
    /// Verifies a signature using the public key stored under <paramref name="keyId"/>.
    /// No biometric authentication is required for verification.
    /// </summary>
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
            // Public key verification — no biometric required.
            var (publicKey, keyError) = AppleKeychainHelpers.RetrieveAsymmetricPublicKey(keyId);
            if (publicKey is null)
                return Task.FromResult(SecureAuthenticationResponse.Failure(keyError!));

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
        catch (Exception ex)
        {
            return Task.FromResult(
                SecureAuthenticationResponse.Failure($"Verify failed: {ex.GetFullMessage()}"));
        }
    }
}
