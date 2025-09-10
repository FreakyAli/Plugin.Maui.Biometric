namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationRequest : BaseAuthenticationRequest
{
    public required string KeyId { get; set; }
    public required byte[] InputData { get; set; }
    public KeyAlgorithm Algorithm { get; set; } = KeyAlgorithm.Aes;
    public BlockMode BlockMode { get; set; } = BlockMode.None;
    public Padding Padding { get; set; } = Padding.None;
    public byte[]? IV { get; set; }

#if ANDROID
    internal string Transformation =>
    AndroidKeyStoreHelpers.MapTransformation(
        AndroidKeyStoreHelpers.MapKeyAlgorithm(Algorithm),
        AndroidKeyStoreHelpers.MapBlockMode(BlockMode),
        AndroidKeyStoreHelpers.MapPadding(Padding));
#endif
}