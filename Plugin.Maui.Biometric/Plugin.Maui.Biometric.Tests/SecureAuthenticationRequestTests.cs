using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class SecureAuthenticationRequestTests
{
    private static SecureAuthenticationRequest BuildRequest(
        string keyId = "test-key",
        byte[]? inputData = null) =>
        new()
        {
            KeyId     = keyId,
            InputData = inputData ?? [1, 2, 3]
        };

    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var request = BuildRequest();

        Assert.Equal(KeyAlgorithm.Aes, request.Algorithm);
        Assert.Equal(BlockMode.None, request.BlockMode);
        Assert.Equal(Padding.None, request.Padding);
        Assert.Null(request.IV);
    }

    [Fact]
    public void InheritsFrom_BaseAuthenticationRequest()
    {
        Assert.IsAssignableFrom<BaseAuthenticationRequest>(BuildRequest());
    }

    [Fact]
    public void KeyId_CanBeSet()
    {
        var request = BuildRequest(keyId: "my-key-id");

        Assert.Equal("my-key-id", request.KeyId);
    }

    [Fact]
    public void InputData_CanBeSet()
    {
        byte[] data = [0xDE, 0xAD, 0xBE, 0xEF];
        var request = BuildRequest(inputData: data);

        Assert.Equal(data, request.InputData);
    }

    [Theory]
    [InlineData(KeyAlgorithm.Aes)]
    [InlineData(KeyAlgorithm.Rsa)]
    [InlineData(KeyAlgorithm.Ec)]
    public void Algorithm_AcceptsAllValues(KeyAlgorithm algorithm)
    {
        var request = BuildRequest();
        request.Algorithm = algorithm;

        Assert.Equal(algorithm, request.Algorithm);
    }

    [Theory]
    [InlineData(BlockMode.None)]
    [InlineData(BlockMode.Cbc)]
    [InlineData(BlockMode.Gcm)]
    [InlineData(BlockMode.Ctr)]
    [InlineData(BlockMode.Ecb)]
    public void BlockMode_AcceptsAllValues(BlockMode blockMode)
    {
        var request = BuildRequest();
        request.BlockMode = blockMode;

        Assert.Equal(blockMode, request.BlockMode);
    }

    [Theory]
    [InlineData(Padding.None)]
    [InlineData(Padding.Pkcs7)]
    [InlineData(Padding.Pkcs1)]
    [InlineData(Padding.Oaep)]
    public void Padding_AcceptsAllValues(Padding padding)
    {
        var request = BuildRequest();
        request.Padding = padding;

        Assert.Equal(padding, request.Padding);
    }

    [Fact]
    public void IV_CanBeSet()
    {
        byte[] iv = [0x01, 0x02, 0x03, 0x04];
        var request = BuildRequest();
        request.IV = iv;

        Assert.Equal(iv, request.IV);
    }

    [Fact]
    public void BaseProperties_AreInherited()
    {
        var request = BuildRequest();
        request.Title             = "Authenticate";
        request.AllowPasswordAuth = true;

        Assert.Equal("Authenticate", request.Title);
        Assert.True(request.AllowPasswordAuth);
    }
}
