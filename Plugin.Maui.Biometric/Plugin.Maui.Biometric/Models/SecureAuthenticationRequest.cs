namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationRequest : BaseAuthenticationRequest
{
    public string KeyId { get; set; } 
    public byte[] InputData { get; set; }
}