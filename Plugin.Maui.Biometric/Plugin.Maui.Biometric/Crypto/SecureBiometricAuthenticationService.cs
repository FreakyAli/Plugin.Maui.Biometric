using System.Diagnostics.CodeAnalysis;

namespace Plugin.Maui.Biometric;

[Experimental("BIOCRYPTO001")]
public static class SecureBiometricAuthenticationService
{
    private static readonly Lazy<ISecureBiometric> defaultImpl =
        new(() => new SecureBiometricService(), LazyThreadSafetyMode.PublicationOnly);

    public static ISecureBiometric Default
    {
        get => defaultImpl.Value;
    }
}
