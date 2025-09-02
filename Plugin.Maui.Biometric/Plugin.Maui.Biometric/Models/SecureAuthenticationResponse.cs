namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationResponse
{
    public bool WasSuccessful { get; set; }
    public byte[]? OutputData { get; set; }
    public string? ErrorMessage { get; set; }

    public static SecureAuthenticationResponse Success(byte[] outputData)
    {
        return new SecureAuthenticationResponse
        {
            WasSuccessful = true,
            OutputData = outputData
        };
    }

    public static SecureAuthenticationResponse Failure(string errorMessage)
    {
        return new SecureAuthenticationResponse
        {
            WasSuccessful = false,
            ErrorMessage = errorMessage
        };
    }
}
