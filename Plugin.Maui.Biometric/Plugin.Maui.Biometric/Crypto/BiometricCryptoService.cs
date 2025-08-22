namespace Plugin.Maui.Biometric;

internal partial class BiometricCryptoService : IBiometricCrypto
{
    public partial Task CreateKeyAsync(string keyId, CryptoKeyOptions options, CancellationToken token);  

    public partial Task DeleteKeyAsync(string keyId);

    public partial Task<bool> KeyExistsAsync(string keyId);

    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token);

    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token);

    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token);

    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token); 

    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token);
}
