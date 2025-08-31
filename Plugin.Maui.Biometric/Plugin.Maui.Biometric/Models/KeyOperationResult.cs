namespace Plugin.Maui.Biometric;

public sealed class KeyOperationResult
{
    public bool Success { get; set; }
    public string ErrorMessage { get; set; }
    public string AdditionalInfo { get; set; }
    internal bool ShouldRetry { get; set; } = true;
    internal string SecurityLevelName { get; set; }
}