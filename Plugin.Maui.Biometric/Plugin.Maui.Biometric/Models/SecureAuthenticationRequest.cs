namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationRequest : BaseAuthenticationRequest
{
    public string KeyId { get; set; }
    public byte[] InputData { get; set; }
    public KeyAlgorithm Algorithm { get; set; } = KeyAlgorithm.Aes;
    public BlockMode BlockMode { get; set; } = BlockMode.None;
    public Padding Padding { get; set; } = Padding.None;
    internal string Transformation =>
    AndroidKeyStoreHelpers.MapTransformation(
        AndroidKeyStoreHelpers.MapKeyAlgorithm(Algorithm),
        AndroidKeyStoreHelpers.MapBlockMode(BlockMode),
        AndroidKeyStoreHelpers.MapPadding(Padding));
}