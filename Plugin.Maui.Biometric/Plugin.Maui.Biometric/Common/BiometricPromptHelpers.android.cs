namespace Plugin.Maui.Biometric;

internal static class BiometricPromptHelpers
{
    internal const string ActivityErrorMsg = """
    Your Platform.CurrentActivity either returned null 
    or is not of type `AndroidX.AppCompat.App.AppCompatActivity`, 
    ensure your Activity is of the right type and that 
    its not null when you call this method
    """;

    internal const string ExecutorErrorMsg = """
    Your Platform.CurrentActivity's main executor could not be obtained, 
    ensure your Activity is of the right type and that 
    its not null when you call this method
    """;
}
