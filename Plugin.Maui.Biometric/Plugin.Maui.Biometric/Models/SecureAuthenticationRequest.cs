namespace Plugin.Maui.Biometric;

public sealed class SecureAuthenticationRequest : BaseAuthenticationRequest
{
    private KeyAlgorithm _algorithm = KeyAlgorithm.Aes;
    private BlockMode _blockMode = BlockMode.None;
    private Padding _padding = Padding.None;

    public required string KeyId { get; set; }
    public required byte[] InputData { get; set; }

    public KeyAlgorithm Algorithm
    {
        get => _algorithm;
        set => _algorithm = value;
    }

    public BlockMode BlockMode
    {
        get => _blockMode;
        set => _blockMode = value;
    }

    public Padding Padding
    {
        get => _padding;
        set => _padding = value;
    }

    public byte[]? IV { get; set; }

    public SecureAuthenticationRequest ValidateCryptoOptions()
    {
        if (Algorithm == KeyAlgorithm.Aes && BlockMode == BlockMode.None && Padding == Padding.None)
            throw new InvalidOperationException(
                "AES requires a BlockMode. For GCM set Padding to None; for CBC require a padding scheme (e.g., PKCS7).");
        return this;
    }

#if ANDROID
    internal string Transformation =>
    AndroidKeyStoreHelpers.MapTransformation(
        AndroidKeyStoreHelpers.MapKeyAlgorithm(Algorithm),
        AndroidKeyStoreHelpers.MapBlockMode(BlockMode),
        AndroidKeyStoreHelpers.MapPadding(Padding));
#endif
}