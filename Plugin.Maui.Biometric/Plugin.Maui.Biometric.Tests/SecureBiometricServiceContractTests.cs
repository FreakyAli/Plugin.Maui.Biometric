using Plugin.Maui.Biometric.Tests.Fakes;
using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Tests the expected contract of any <see cref="ISecureBiometric"/> implementation using a fake.
/// These tests define the behaviour that all platform implementations must satisfy.
/// </summary>
public class SecureBiometricServiceContractTests
{
    private readonly FakeSecureBiometricService _sut = new();

    private static SecureAuthenticationRequest BuildRequest(
        string keyId = "test-key",
        byte[]? inputData = null) =>
        new()
        {
            KeyId     = keyId,
            InputData = inputData ?? [1, 2, 3],
            Title     = "Authenticate"
        };

    // ── CreateKeyAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateKeyAsync_OnSuccess_ReturnsSuccessResult()
    {
        _sut.CreateKeyResult = KeyOperationResult.Success("TEE", "Key created.");

        var result = await _sut.CreateKeyAsync("my-key", new CryptoKeyOptions());

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public async Task CreateKeyAsync_OnFailure_ReturnsFailureResult()
    {
        _sut.CreateKeyResult = KeyOperationResult.Failure("Keystore error");

        var result = await _sut.CreateKeyAsync("my-key", new CryptoKeyOptions());

        Assert.False(result.WasSuccessful);
        Assert.Equal("Keystore error", result.ErrorMessage);
    }

    [Fact]
    public async Task CreateKeyAsync_ReturnsNonNullResult()
    {
        var result = await _sut.CreateKeyAsync("key", new CryptoKeyOptions());

        Assert.NotNull(result);
    }

    // ── DeleteKeyAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteKeyAsync_OnSuccess_ReturnsSuccessResult()
    {
        _sut.DeleteKeyResult = KeyOperationResult.Success(additionalInfo: "Deleted.");

        var result = await _sut.DeleteKeyAsync("my-key");

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public async Task DeleteKeyAsync_OnFailure_ReturnsFailureResult()
    {
        _sut.DeleteKeyResult = KeyOperationResult.Failure("Key not found");

        var result = await _sut.DeleteKeyAsync("my-key");

        Assert.False(result.WasSuccessful);
        Assert.Equal("Key not found", result.ErrorMessage);
    }

    // ── KeyExistsAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task KeyExistsAsync_WhenKeyExists_ReturnsSuccess()
    {
        _sut.KeyExistsResult = KeyOperationResult.Success(additionalInfo: "Key 'x' exists.");

        var result = await _sut.KeyExistsAsync("x");

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public async Task KeyExistsAsync_WhenKeyDoesNotExist_ReturnsFailure()
    {
        _sut.KeyExistsResult = KeyOperationResult.Failure("Key 'x' does not exist.");

        var result = await _sut.KeyExistsAsync("x");

        Assert.False(result.WasSuccessful);
    }

    // ── EncryptAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task EncryptAsync_OnSuccess_ReturnsSuccessResponse()
    {
        byte[] ciphertext = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] iv         = [0x01, 0x02, 0x03];
        _sut.EncryptResult = SecureAuthenticationResponse.Success(ciphertext, iv);

        var result = await _sut.EncryptAsync(BuildRequest(), CancellationToken.None);

        Assert.True(result.WasSuccessful);
        Assert.Equal(ciphertext, result.OutputData);
        Assert.Equal(iv, result.IV);
    }

    [Fact]
    public async Task EncryptAsync_OnFailure_ReturnsFailureResponse()
    {
        _sut.EncryptResult = SecureAuthenticationResponse.Failure("Key not found");

        var result = await _sut.EncryptAsync(BuildRequest(), CancellationToken.None);

        Assert.False(result.WasSuccessful);
        Assert.Equal("Key not found", result.ErrorMessage);
    }

    [Fact]
    public async Task EncryptAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _sut.EncryptAsync(BuildRequest(), cts.Token));
    }

    [Fact]
    public async Task EncryptAsync_ReturnsNonNullResponse()
    {
        var result = await _sut.EncryptAsync(BuildRequest(), CancellationToken.None);

        Assert.NotNull(result);
    }

    // ── DecryptAsync ──────────────────────────────────────────────────────────

    [Fact]
    public async Task DecryptAsync_OnSuccess_ReturnsSuccessResponse()
    {
        byte[] plaintext = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
        _sut.DecryptResult = SecureAuthenticationResponse.Success(plaintext);

        var result = await _sut.DecryptAsync(BuildRequest(), CancellationToken.None);

        Assert.True(result.WasSuccessful);
        Assert.Equal(plaintext, result.OutputData);
    }

    [Fact]
    public async Task DecryptAsync_OnFailure_ReturnsFailureResponse()
    {
        _sut.DecryptResult = SecureAuthenticationResponse.Failure("Authentication cancelled");

        var result = await _sut.DecryptAsync(BuildRequest(), CancellationToken.None);

        Assert.False(result.WasSuccessful);
        Assert.Equal("Authentication cancelled", result.ErrorMessage);
    }

    [Fact]
    public async Task DecryptAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _sut.DecryptAsync(BuildRequest(), cts.Token));
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNonNullResponse()
    {
        var result = await _sut.DecryptAsync(BuildRequest(), CancellationToken.None);

        Assert.NotNull(result);
    }

    // ── SignAsync ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_OnSuccess_ReturnsSuccessResponse()
    {
        byte[] signature = [0xAA, 0xBB, 0xCC, 0xDD];
        _sut.SignResult = SecureAuthenticationResponse.Success(signature);

        var result = await _sut.SignAsync("test-key", [1, 2, 3],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.True(result.WasSuccessful);
        Assert.Equal(signature, result.OutputData);
    }

    [Fact]
    public async Task SignAsync_OnFailure_ReturnsFailureResponse()
    {
        _sut.SignResult = SecureAuthenticationResponse.Failure("Signing not supported");

        var result = await _sut.SignAsync("test-key", [1, 2, 3],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.False(result.WasSuccessful);
        Assert.Equal("Signing not supported", result.ErrorMessage);
    }

    [Fact]
    public async Task SignAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _sut.SignAsync("test-key", [1, 2, 3],
                KeyAlgorithm.Ec, Digest.Sha256, cts.Token));
    }

    [Fact]
    public async Task SignAsync_PassesAlgorithmAndDigestToImplementation()
    {
        await _sut.SignAsync("key", [1], KeyAlgorithm.Rsa, Digest.Sha512, CancellationToken.None);

        Assert.Equal(KeyAlgorithm.Rsa, _sut.LastSignAlgorithm);
        Assert.Equal(Digest.Sha512, _sut.LastSignDigest);
    }

    [Fact]
    public async Task SignAsync_ReturnsNonNullResponse()
    {
        var result = await _sut.SignAsync("key", [1, 2, 3],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.NotNull(result);
    }

    // ── VerifyAsync ───────────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_OnSuccess_ReturnsSuccessResponse()
    {
        _sut.VerifyResult = SecureAuthenticationResponse.Success(Array.Empty<byte>());

        var result = await _sut.VerifyAsync("test-key", [1, 2, 3], [4, 5, 6],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.True(result.WasSuccessful);
    }

    [Fact]
    public async Task VerifyAsync_OnFailure_ReturnsFailureResponse()
    {
        _sut.VerifyResult = SecureAuthenticationResponse.Failure("Signature invalid");

        var result = await _sut.VerifyAsync("test-key", [1, 2, 3], [4, 5, 6],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.False(result.WasSuccessful);
        Assert.Equal("Signature invalid", result.ErrorMessage);
    }

    [Fact]
    public async Task VerifyAsync_WhenCancelled_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _sut.VerifyAsync("test-key", [1, 2, 3], [4, 5, 6],
                KeyAlgorithm.Ec, Digest.Sha256, cts.Token));
    }

    [Fact]
    public async Task VerifyAsync_PassesAlgorithmAndDigestToImplementation()
    {
        await _sut.VerifyAsync("key", [1], [2], KeyAlgorithm.Rsa, Digest.Sha384, CancellationToken.None);

        Assert.Equal(KeyAlgorithm.Rsa, _sut.LastVerifyAlgorithm);
        Assert.Equal(Digest.Sha384, _sut.LastVerifyDigest);
    }

    [Fact]
    public async Task VerifyAsync_ReturnsNonNullResponse()
    {
        var result = await _sut.VerifyAsync("key", [1, 2, 3], [4, 5, 6],
            KeyAlgorithm.Ec, Digest.Sha256, CancellationToken.None);

        Assert.NotNull(result);
    }
}
