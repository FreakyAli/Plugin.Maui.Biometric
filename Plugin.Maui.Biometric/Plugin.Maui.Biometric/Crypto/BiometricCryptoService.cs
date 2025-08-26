namespace Plugin.Maui.Biometric;

internal partial class BiometricCryptoService : IBiometricCrypto
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options);  

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<KeyOperationResult> DeleteKeyAsync(string keyId);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<bool> KeyExistsAsync(string keyId);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureCryptoResponse> DecryptAsync(string keyId, byte[] inputData, CancellationToken token);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureCryptoResponse> EncryptAsync(string keyId, byte[] inputData, CancellationToken token);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureCryptoResponse> MacAsync(string keyId, byte[] inputData, CancellationToken token);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureCryptoResponse> SignAsync(string keyId, byte[] inputData, CancellationToken token); 

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Interface abstraction requires instance method.")]
    public partial Task<SecureCryptoResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, CancellationToken token);
}
