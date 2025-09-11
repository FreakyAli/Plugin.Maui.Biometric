namespace Plugin.Maui.Biometric;
internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        return Task.FromResult(KeyOperationResult.Success());
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        return Task.FromResult(KeyOperationResult.Success());
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    {
        return Task.FromResult(KeyOperationResult.Success());
    }

    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        return Task.FromResult(new SecureAuthenticationResponse());
    }

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        return Task.FromResult(new SecureAuthenticationResponse());
    }   
    
    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        return Task.FromResult(new SecureAuthenticationResponse());
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        return Task.FromResult(new SecureAuthenticationResponse());
    }
}
