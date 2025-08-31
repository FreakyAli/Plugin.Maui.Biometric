namespace Plugin.Maui.Biometric;

public sealed class AuthenticationRequest
{
    public bool AllowPasswordAuth { get; set; }
    public string Title { get; set; }
    public string Subtitle { get; set; }
    public string NegativeText { get; set; }
    /// <summary>
    /// On Windows Platform with WindowsHello, this propery is used as a message for auth
    /// </summary>
    public string? Description { get; set; }
    public AuthenticatorStrength AuthStrength { get; set; }
}