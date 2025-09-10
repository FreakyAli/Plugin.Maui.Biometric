
namespace Plugin.Maui.Biometric;

public abstract class BaseAuthenticationRequest
{
    public bool AllowPasswordAuth { get; set; }

#nullable disable
    public string Title { get; set; }
    public string Subtitle { get; set; }
    public string NegativeText { get; set; }
#nullable restore

    /// <summary>
    /// On Windows Platform with Windows Hello, this property is used as a message for auth
    /// </summary>
    public string? Description { get; set; }
    public AuthenticatorStrength AuthStrength { get; set; }
}
