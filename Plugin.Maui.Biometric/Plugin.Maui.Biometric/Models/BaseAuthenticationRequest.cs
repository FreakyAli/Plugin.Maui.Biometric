namespace Plugin.Maui.Biometric;

public abstract class BaseAuthenticationRequest
{
    public bool AllowPasswordAuth { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Subtitle { get; set; } = string.Empty;
    public string NegativeText { get; set; } = string.Empty;

    /// <summary>
    /// On Windows Platform with Windows Hello, this property is used as a message for auth
    /// </summary>
    public string? Description { get; set; }
    public AuthenticatorStrength AuthStrength { get; set; }
}
