namespace Plugin.Maui.Biometric;

public static class BiometricCryptoAuthenticationService
{
    private static readonly Lazy<ISecureBiometric> defaultImpl =
        new(() => new BiometricCryptoService(), LazyThreadSafetyMode.PublicationOnly);

    public static ISecureBiometric Default
    {
        get => defaultImpl.Value;
    }
}