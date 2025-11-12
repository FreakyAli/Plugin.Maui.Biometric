namespace Plugin.Maui.Biometric;

[Flags]
public enum CryptoOperation
{
    None = 0,
    Encrypt = 1 << 0,
    Decrypt = 1 << 1,
    Sign = 1 << 2,
    Verify = 1 << 3,
    Mac = 1 << 4
}
