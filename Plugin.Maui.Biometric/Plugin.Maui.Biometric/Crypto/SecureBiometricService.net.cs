namespace Plugin.Maui.Biometric;
partial class SecureBiometricService
{
    private static readonly PlatformNotSupportedException s_secureBiometricNotSupported =
        new("Secure biometric operations are not supported on this platform.");

    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
        => Task.FromException<KeyOperationResult>(s_secureBiometricNotSupported);

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
        => Task.FromException<KeyOperationResult>(s_secureBiometricNotSupported);

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
        => Task.FromException<KeyOperationResult>(s_secureBiometricNotSupported);

    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => Task.FromException<SecureAuthenticationResponse>(s_secureBiometricNotSupported);

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
        => Task.FromException<SecureAuthenticationResponse>(s_secureBiometricNotSupported);

    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
        => Task.FromException<SecureAuthenticationResponse>(s_secureBiometricNotSupported);

    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
        => Task.FromException<SecureAuthenticationResponse>(s_secureBiometricNotSupported);
}
