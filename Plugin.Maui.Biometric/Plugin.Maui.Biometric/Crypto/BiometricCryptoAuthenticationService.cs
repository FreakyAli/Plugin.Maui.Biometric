namespace Plugin.Maui.Biometric;

public static class BiometricCryptoAuthenticationService
{
    private static readonly Lazy<IBiometricCrypto> defaultImpl =
        new(() => new BiometricCryptoService(), LazyThreadSafetyMode.PublicationOnly);

    public static IBiometricCrypto Default
    {
        get => defaultImpl.Value;
    }
}