namespace Plugin.Maui.Biometric;

public sealed class SecureCryptoResponse
{
    public bool WasSuccessful { get; set; }
    public byte[]? OutputData { get; set; }
    public string? ErrorMessage { get; set; }

    public static SecureCryptoResponse Success(byte[] outputData)
    {
        return new SecureCryptoResponse
        {
            WasSuccessful = true,
            OutputData = outputData
        };
    }

    public static SecureCryptoResponse Failed(string errorMessage)
    {
        return new SecureCryptoResponse
        {
            WasSuccessful = false,
            ErrorMessage = errorMessage
        };
    }
}
