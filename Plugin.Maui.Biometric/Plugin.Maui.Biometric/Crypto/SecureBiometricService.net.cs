namespace Plugin.Maui.Biometric;
partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    {
        throw new NotImplementedException();
    }

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        throw new NotImplementedException();
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    { 
        throw new NotImplementedException();
    }
    
    public partial Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureAuthenticationResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        throw new NotImplementedException();
    }
}