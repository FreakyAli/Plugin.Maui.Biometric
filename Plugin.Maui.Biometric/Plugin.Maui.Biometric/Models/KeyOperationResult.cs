namespace Plugin.Maui.Biometric;

public sealed class KeyOperationResult
{
    private KeyOperationResult() { }
    public bool WasSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
    public string? AdditionalInfo { get; set; }
    internal string? SecurityLevelName { get; set; }

    public static KeyOperationResult Success(string? securityLevelName = null, string? additionalInfo = null)
    => new()
    {
        WasSuccessful = true,
        SecurityLevelName = securityLevelName,
        AdditionalInfo = additionalInfo
    };

    public static KeyOperationResult Failure(string errorMessage, string? additionalInfo = null)
    => new()
    {
        WasSuccessful = false,
        ErrorMessage = errorMessage,
        AdditionalInfo = additionalInfo
    };
}