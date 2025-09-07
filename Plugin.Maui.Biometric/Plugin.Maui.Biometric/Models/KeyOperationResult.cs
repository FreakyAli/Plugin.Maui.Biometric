namespace Plugin.Maui.Biometric;

public sealed class KeyOperationResult
{
    public bool Success { get; set; }
    public string ErrorMessage { get; set; }
    public Exception? Exception { get; set; } 
    public string AdditionalInfo { get; set; }
    internal string SecurityLevelName { get; set; }
}