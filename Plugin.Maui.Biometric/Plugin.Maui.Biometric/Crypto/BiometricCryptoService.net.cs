namespace Plugin.Maui.Biometric;
partial class BiometricCryptoService
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
    
    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        throw new NotImplementedException();
    }
}