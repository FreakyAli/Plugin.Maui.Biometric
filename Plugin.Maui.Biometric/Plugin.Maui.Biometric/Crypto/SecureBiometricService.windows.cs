namespace Plugin.Maui.Biometric;

internal partial class SecureBiometricService
{
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
    { 
        return Task.FromResult(new KeyOperationResult());
    }  

    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId)
    {
        return Task.FromResult(new KeyOperationResult());
    }

    public partial Task<KeyOperationResult> KeyExistsAsync(string keyId)
    { 
        return Task.FromResult(new KeyOperationResult());
    }

    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }   

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }
}