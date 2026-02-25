using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class CryptoKeyOptionsTests
{
    [Fact]
    public void DefaultValues_AreCorrect()
    {
        var options = new CryptoKeyOptions();

        Assert.Equal(KeyAlgorithm.Aes, options.Algorithm);
        Assert.Equal(CryptoOperation.Encrypt | CryptoOperation.Decrypt, options.Operation);
        Assert.Equal(256, options.KeySize);
        Assert.True(options.RequireUserAuthentication);
        Assert.Equal(BlockMode.Gcm, options.BlockMode);
        Assert.Equal(Padding.None, options.Padding);
        Assert.Equal(Digest.Sha256, options.Digest);
    }

    [Theory]
    [InlineData(KeyAlgorithm.Aes)]
    [InlineData(KeyAlgorithm.Rsa)]
    [InlineData(KeyAlgorithm.Ec)]
    public void Algorithm_AcceptsAllValues(KeyAlgorithm algorithm)
    {
        var options = new CryptoKeyOptions { Algorithm = algorithm };

        Assert.Equal(algorithm, options.Algorithm);
    }

    [Theory]
    [InlineData(BlockMode.None)]
    [InlineData(BlockMode.Cbc)]
    [InlineData(BlockMode.Gcm)]
    [InlineData(BlockMode.Ctr)]
    [InlineData(BlockMode.Ecb)]
    public void BlockMode_AcceptsAllValues(BlockMode blockMode)
    {
        var options = new CryptoKeyOptions { BlockMode = blockMode };

        Assert.Equal(blockMode, options.BlockMode);
    }

    [Theory]
    [InlineData(Padding.None)]
    [InlineData(Padding.Pkcs7)]
    [InlineData(Padding.Pkcs1)]
    [InlineData(Padding.Oaep)]
    public void Padding_AcceptsAllValues(Padding padding)
    {
        var options = new CryptoKeyOptions { Padding = padding };

        Assert.Equal(padding, options.Padding);
    }

    [Theory]
    [InlineData(Digest.None)]
    [InlineData(Digest.Sha1)]
    [InlineData(Digest.Sha224)]
    [InlineData(Digest.Sha256)]
    [InlineData(Digest.Sha384)]
    [InlineData(Digest.Sha512)]
    public void Digest_AcceptsAllValues(Digest digest)
    {
        var options = new CryptoKeyOptions { Digest = digest };

        Assert.Equal(digest, options.Digest);
    }

    [Theory]
    [InlineData(CryptoOperation.Encrypt)]
    [InlineData(CryptoOperation.Decrypt)]
    [InlineData(CryptoOperation.Sign)]
    [InlineData(CryptoOperation.Verify)]
    [InlineData(CryptoOperation.Encrypt | CryptoOperation.Decrypt)]
    [InlineData(CryptoOperation.Sign | CryptoOperation.Verify)]
    public void Operation_AcceptsSingleAndCombinedFlags(CryptoOperation operation)
    {
        var options = new CryptoKeyOptions { Operation = operation };

        Assert.Equal(operation, options.Operation);
    }

    [Theory]
    [InlineData(128)]
    [InlineData(256)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void KeySize_CanBeSet(int keySize)
    {
        var options = new CryptoKeyOptions { KeySize = keySize };

        Assert.Equal(keySize, options.KeySize);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RequireUserAuthentication_CanBeToggled(bool require)
    {
        var options = new CryptoKeyOptions { RequireUserAuthentication = require };

        Assert.Equal(require, options.RequireUserAuthentication);
    }
}
