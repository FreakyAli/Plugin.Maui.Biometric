namespace Plugin.Maui.Biometric;

public class AuthenticationRequest
{
    public bool AllowPasswordAuth { get; set; }
    public string Title { get; set; }
    public string Subtitle { get; set; }
    public string NegativeText { get; set; }
    public string Description { get; set; }
    public AuthenticatorStrength AuthStrength { get; set; }
}