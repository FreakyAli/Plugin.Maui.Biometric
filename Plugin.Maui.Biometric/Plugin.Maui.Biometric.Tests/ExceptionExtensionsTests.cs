using Xunit;

namespace Plugin.Maui.Biometric.Tests;

public class ExceptionExtensionsTests
{
    [Fact]
    public void GetFullMessage_NullException_ReturnsEmptyString()
    {
        Exception? ex = null;

        var result = ex!.GetFullMessage();

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void GetFullMessage_SimpleException_ReturnsMessage()
    {
        var ex = new InvalidOperationException("Something went wrong");

        var result = ex.GetFullMessage();

        Assert.Equal("Something went wrong", result);
    }

    [Fact]
    public void GetFullMessage_WithInnerException_ChainsMessages()
    {
        var inner = new ArgumentNullException("param", "param is null");
        var outer = new InvalidOperationException("Outer error", inner);

        var result = outer.GetFullMessage();

        Assert.Contains("Outer error", result);
        Assert.Contains(" --> ", result);
        Assert.Contains("param is null", result);
    }

    [Fact]
    public void GetFullMessage_WithDoublyNestedInnerException_ChainsAllMessages()
    {
        var root    = new Exception("Root cause");
        var middle  = new Exception("Middle error", root);
        var outerEx = new Exception("Outer error", middle);

        var result = outerEx.GetFullMessage();

        Assert.Contains("Outer error", result);
        Assert.Contains("Middle error", result);
        Assert.Contains("Root cause", result);
    }

    [Fact]
    public void GetFullMessage_WithNoInnerException_DoesNotContainSeparator()
    {
        var ex = new Exception("Only message");

        var result = ex.GetFullMessage();

        Assert.DoesNotContain(" --> ", result);
    }
}
