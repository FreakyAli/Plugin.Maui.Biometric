namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationResponse
{
    public bool WasSuccessful { get; private set; }
    public byte[]? OutputData { get; private set; }
    public byte[]? IV { get; set; }
    public string? ErrorMessage { get; private set; }

    public static SecureAuthenticationResponse Success(byte[] outputData, byte[]? iv = null)
    {
        return new SecureAuthenticationResponse
        {
            WasSuccessful = true,
            OutputData = (byte[])outputData.Clone(),
            IV = iv is null ? null : (byte[])iv.Clone()
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