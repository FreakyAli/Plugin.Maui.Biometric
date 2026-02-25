namespace Plugin.Maui.Biometric.Tests.Fakes;

internal class FakeSecureBiometricService : ISecureBiometric
{
    public KeyOperationResult CreateKeyResult    { get; set; } = KeyOperationResult.Success();
    public KeyOperationResult DeleteKeyResult    { get; set; } = KeyOperationResult.Success();
    public KeyOperationResult KeyExistsResult    { get; set; } = KeyOperationResult.Success();
    public SecureAuthenticationResponse EncryptResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());
    public SecureAuthenticationResponse DecryptResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());

    public Task<KeyOperationResult> CreateKeyAsync(string keyId, CryptoKeyOptions options)
        => Task.FromResult(CreateKeyResult);

    public Task<KeyOperationResult> DeleteKeyAsync(string keyId)
        => Task.FromResult(DeleteKeyResult);

    public Task<KeyOperationResult> KeyExistsAsync(string keyId)
        => Task.FromResult(KeyExistsResult);

    public Task<SecureAuthenticationResponse> EncryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(EncryptResult);
    }

    public Task<SecureAuthenticationResponse> DecryptAsync(SecureAuthenticationRequest request, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        return Task.FromResult(DecryptResult);
    }
}
