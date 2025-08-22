namespace Plugin.Maui.Biometric;
internal partial class BiometricCryptoService
{
    public partial Task CreateKeyAsync(string keyId, CryptoKeyOptions options, CancellationToken token)
    { 
        return Task.CompletedTask;
    }  

    public partial Task DeleteKeyAsync(string keyId)
    {
        return Task.CompletedTask;
    }

    public partial Task<bool> KeyExistsAsync(string keyId)
    { 
        return Task.FromResult(false);
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
