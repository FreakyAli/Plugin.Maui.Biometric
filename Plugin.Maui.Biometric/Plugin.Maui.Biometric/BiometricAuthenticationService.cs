namespace Plugin.Maui.Biometric;
[Preserve(AllMembers = true)]
public static class BiometricAuthenticationService
{
    private static readonly Lazy<IBiometric> defaultImpl =
        new(() => new BiometricService(), LazyThreadSafetyMode.PublicationOnly);

    public static IBiometric Default
    {
        get => defaultImpl.Value;
    }
}