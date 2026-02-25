using System.Security.Cryptography;
using Windows.Security.Credentials;
using Windows.Security.Credentials.UI;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace Plugin.Maui.Biometric;

/// <summary>
/// Orchestrates biometric-gated cryptographic operations on Windows.
/// Mirrors <c>LAContextCryptoHelpers</c> on iOS/macOS.
/// </summary>
internal static class WindowsHelloCryptoHelpers
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
    /// Requests Windows Hello / biometric verification.
    /// Mirrors <c>AuthenticateAsync</c> in <c>LAContextCryptoHelpers</c>.
    /// </summary>
    private static async Task<(bool verified, string? error)> AuthenticateAsync(
        string message, CancellationToken token)
    {
        var availability = await UserConsentVerifier.CheckAvailabilityAsync();
        if (availability != UserConsentVerifierAvailability.Available)
            return (false, "Windows Hello is not available on this device.");

        try
        {
            using (token.Register(() => { }))
            {
                var result = await UserConsentVerifier.RequestVerificationAsync(message);
                return result == UserConsentVerificationResult.Verified
                    ? (true, null)
                    : (false, $"Authentication failed: {result}");
            }
        }
        catch (OperationCanceledException)
        {
            return (false, "Authentication was cancelled.");
        }
        catch (Exception ex)
        {
            return (false, $"Authentication error: {ex.GetFullMessage()}");
        }
    }

    // ─── AES-GCM (symmetric) ─────────────────────────────────────────────────

    /// <summary>
    /// Encrypts or decrypts data with the AES key stored in PasswordVault.
    /// <para>
    /// Encrypt output format: <c>OutputData</c> = ciphertext ‖ 16-byte GCM tag,
    /// <c>IV</c> = 12-byte nonce.  This matches the GCM output format produced by
    /// Android and Apple, so payloads are cross-platform compatible.
    /// </para>
    /// </summary>
    internal static async Task<SecureAuthenticationResponse> ProcessAesCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
    {
        var validation = ValidateRequest(request);
        if (validation is not null) return validation;

        var (verified, authError) = await AuthenticateAsync(request.Title, token);
        if (!verified)
            return SecureAuthenticationResponse.Failure(authError!);

        try
        {
            var (keyBytes, keyError) = WindowsKeyVaultHelpers.RetrieveSymmetricKey(request.KeyId);
            if (keyBytes is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            if (encrypt)
            {
                var iv         = RandomNumberGenerator.GetBytes(12);  // 96-bit nonce
                var ciphertext = new byte[request.InputData.Length];
                var tag        = new byte[16];                         // 128-bit auth tag

                using var aesGcm = new AesGcm(keyBytes, 16);
                aesGcm.Encrypt(iv, request.InputData, ciphertext, tag);

                // Append tag to ciphertext — matches Android/Apple GCM output layout.
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
    }

    // ─── RSA (asymmetric encrypt / decrypt) ───────────────────────────────────

    /// <summary>
    /// RSA encrypt/decrypt is not supported via Windows Hello — Windows Hello keys
    /// only support signing.  Use AES for encryption or EC/RSA for signing instead.
    /// </summary>
    internal static Task<SecureAuthenticationResponse> ProcessRsaCryptoAsync(
        SecureAuthenticationRequest request, bool encrypt, CancellationToken token)
        => Task.FromResult(SecureAuthenticationResponse.Failure(
            "RSA encrypt/decrypt is not supported on Windows. Use AES for encryption or EC for signing."));

    // ─── Sign (Windows Hello) ──────────────────────────────────────────────────

    /// <summary>
    /// Signs <paramref name="inputData"/> using the Windows Hello key credential.
    /// Biometric authentication is triggered automatically by the Windows Hello prompt.
    /// </summary>
    internal static async Task<SecureAuthenticationResponse> ProcessSignAsync(
        string keyId, byte[] inputData, CancellationToken token)
    {
        try
        {
            var (credential, keyError) = await WindowsKeyVaultHelpers.OpenWindowsHelloKeyAsync(keyId);
            if (credential is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            var buffer     = CryptographicBuffer.CreateFromByteArray(inputData);
            var signResult = await credential.RequestSignAsync(buffer);

            if (signResult.Status != KeyCredentialStatus.Success)
                return SecureAuthenticationResponse.Failure($"Signing failed: {signResult.Status}");

            CryptographicBuffer.CopyToByteArray(signResult.Result, out byte[] signatureBytes);
            return SecureAuthenticationResponse.Success(signatureBytes);
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"Sign failed: {ex.GetFullMessage()}");
        }
    }

    // ─── Verify (Windows Hello public key) ────────────────────────────────────

    /// <summary>
    /// Verifies a signature using the Windows Hello public key.
    /// No biometric authentication is required for verification.
    /// </summary>
    internal static async Task<SecureAuthenticationResponse> ProcessVerifyAsync(
        string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        try
        {
            var (credential, keyError) = await WindowsKeyVaultHelpers.OpenWindowsHelloKeyAsync(keyId);
            if (credential is null)
                return SecureAuthenticationResponse.Failure(keyError!);

            var publicKey = credential.RetrievePublicKey();
            var algorithm = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(
                AsymmetricAlgorithmNames.RsaSignPkcs1Sha256);
            var cryptoKey = algorithm.ImportPublicKey(publicKey);

            var dataBuffer      = CryptographicBuffer.CreateFromByteArray(inputData);
            var signatureBuffer = CryptographicBuffer.CreateFromByteArray(signature);

            bool valid = CryptographicEngine.VerifySignature(cryptoKey, dataBuffer, signatureBuffer);
            return valid
                ? SecureAuthenticationResponse.Success(Array.Empty<byte>())
                : SecureAuthenticationResponse.Failure("Signature verification failed.");
        }
        catch (Exception ex)
        {
            return SecureAuthenticationResponse.Failure($"Verify failed: {ex.GetFullMessage()}");
        }
    }
}
