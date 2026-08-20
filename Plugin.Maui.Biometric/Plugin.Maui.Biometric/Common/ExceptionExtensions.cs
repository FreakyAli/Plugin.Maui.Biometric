namespace Plugin.Maui.Biometric;

internal static class ExceptionExtensions
{
    public static string GetFullMessage(this Exception ex)
    {
        if (ex is null)
            return string.Empty;

        var message = ex.Message;

        if (ex.InnerException != null)
        {
            message += " --> " + ex.InnerException.GetFullMessage();
        }
        return message;
    }

#if IOS || MACCATALYST
    public static string GetErrorMessage(this Foundation.NSError error)
    {
        if (error is null)
            return string.Empty;

        return $"Domain: {error.Domain}, Code: {error.Code}, Description: {error.LocalizedDescription}, FailureReason: {error.LocalizedFailureReason}, RecoverySuggestion: {error.LocalizedRecoverySuggestion}";
    }
#endif
}
