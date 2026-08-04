namespace Plugin.Maui.Biometric;
partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        throw new PlatformNotSupportedException("Secure biometric operations are not supported on this platform.");
    }
}
