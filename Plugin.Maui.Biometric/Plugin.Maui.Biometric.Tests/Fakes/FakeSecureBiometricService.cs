namespace Plugin.Maui.Biometric.Tests.Fakes;

internal class FakeSecureBiometricService : ISecureBiometric
{
    public KeyOperationResult CreateKeyResult    { get; set; } = KeyOperationResult.Success();
    public KeyOperationResult DeleteKeyResult    { get; set; } = KeyOperationResult.Success();
    public KeyOperationResult KeyExistsResult    { get; set; } = KeyOperationResult.Success();
    public SecureAuthenticationResponse EncryptResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());
    public SecureAuthenticationResponse DecryptResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());
    public SecureAuthenticationResponse SignResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());
    public SecureAuthenticationResponse VerifyResult { get; set; } = SecureAuthenticationResponse.Success(Array.Empty<byte>());

    // Capture last-used algorithm/digest for assertions
    public KeyAlgorithm? LastSignAlgorithm { get; private set; }
    public Digest? LastSignDigest { get; private set; }
    public KeyAlgorithm? LastVerifyAlgorithm { get; private set; }
    public Digest? LastVerifyDigest { get; private set; }

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

    public Task<SecureAuthenticationResponse> SignAsync(string keyId, byte[] inputData, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        LastSignAlgorithm = algorithm;
        LastSignDigest = digest;
        return Task.FromResult(SignResult);
    }

    public Task<SecureAuthenticationResponse> VerifyAsync(string keyId, byte[] inputData, byte[] signature, KeyAlgorithm algorithm, Digest digest, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        LastVerifyAlgorithm = algorithm;
        LastVerifyDigest = digest;
        return Task.FromResult(VerifyResult);
    }
}
