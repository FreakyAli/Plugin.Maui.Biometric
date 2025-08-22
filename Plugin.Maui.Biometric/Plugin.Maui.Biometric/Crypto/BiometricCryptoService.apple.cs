namespace Plugin.Maui.Biometric;
partial class BiometricCryptoService
{
    public partial Task CreateKeyAsync(string keyId, CryptoKeyOptions options, CancellationToken token = default)
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

    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token = default)
    {
        return Task.FromResult(new SecureCryptoResponse());
    }
}
