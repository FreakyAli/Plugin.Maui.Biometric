using Xunit;

namespace Plugin.Maui.Biometric.Tests;

/// <summary>
/// Guards against regressions where the default crypto parameters on
/// <see cref="CryptoKeyOptions"/> and <see cref="SecureAuthenticationRequest"/>
/// drift apart. A mismatch means the happy path (create key with defaults →
/// encrypt with defaults) would fail on Android/Windows.
/// </summary>
public class DefaultConsistencyTests
{
    [Fact]
    public void BlockMode_Default_MatchesBetween_KeyOptions_And_Request()
    {
        var options = new CryptoKeyOptions();
        var request = new SecureAuthenticationRequest
        {
            KeyId = "test",
            InputData = [1, 2, 3]
        };

        Assert.Equal(options.BlockMode, request.BlockMode);
    }

    [Fact]
    public void Padding_Default_MatchesBetween_KeyOptions_And_Request()
    {
        var options = new CryptoKeyOptions();
        var request = new SecureAuthenticationRequest
        {
            KeyId = "test",
            InputData = [1, 2, 3]
        };

        Assert.Equal(options.Padding, request.Padding);
    }

    [Fact]
    public void Algorithm_Default_MatchesBetween_KeyOptions_And_Request()
    {
        var options = new CryptoKeyOptions();
        var request = new SecureAuthenticationRequest
        {
            KeyId = "test",
            InputData = [1, 2, 3]
        };

        Assert.Equal(options.Algorithm, request.Algorithm);
    }

    [Fact]
    public void CryptoKeyOptions_Defaults_AreValid_ForKeyCreation()
    {
        var options = new CryptoKeyOptions();
        var result = KeyCreationHelpers.PerformKeyCreationValidation("test-key", options);

        Assert.True(result.WasSuccessful);
    }
}
