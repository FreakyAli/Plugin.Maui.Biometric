namespace Plugin.Maui.Biometric;

public sealed class SecureCryptoResponse
{
    public bool WasSuccessful { get; set; }
    public byte[]? OutputData { get; set; }
    public string? ErrorMessage { get; set; }
}
