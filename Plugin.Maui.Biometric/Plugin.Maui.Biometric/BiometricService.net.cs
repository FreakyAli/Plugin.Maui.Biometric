namespace Plugin.Maui.Biometric;
#if NET && !ANDROID && !IOS && !WINDOWS && !MACCATALYST
[Preserve(AllMembers = true)]
internal partial class BiometricService : IBiometric
{
    public partial Task<AuthenticationResponse> AuthenticateAsync(AuthenticationRequest request, CancellationToken token)
    {
        throw new NotImplementedException();
    }

    public partial Task<BiometricHwStatus> GetAuthenticationStatusAsync(AuthenticatorStrength authStrength)
    {
        throw new NotImplementedException();
    }

    public partial Task<BiometricType[]> GetEnrolledBiometricTypesAsync()
    {
        throw new NotImplementedException();
    }

    private static partial bool GetIsPlatformSupported() => false;

    public void Dispose()
    {
        throw new NotImplementedException();
    }
}
#endif