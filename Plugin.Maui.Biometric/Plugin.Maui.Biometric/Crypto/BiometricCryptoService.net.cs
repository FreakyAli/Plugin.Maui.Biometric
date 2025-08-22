namespace Plugin.Maui.Biometric;
#if NET && !ANDROID && !IOS && !WINDOWS && !MACCATALYST
partial class BiometricCryptoService
{
    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }
    
    public partial Task CreateKeyAsync(string keyId, CryptoKeyOptions options, CancellationToken token = default)
    {
        throw new NotImplementedException();
    }
}
#endif