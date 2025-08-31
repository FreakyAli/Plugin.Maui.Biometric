namespace Plugin.Maui.Biometric;

public static class SecureBiometricAuthenticationService
{
    private static readonly Lazy<ISecureBiometric> defaultImpl =
        new(() => new SecureBiometricService(), LazyThreadSafetyMode.PublicationOnly);

    public static ISecureBiometric Default
    {
        get => defaultImpl.Value;
    }
}