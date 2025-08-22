namespace Plugin.Maui.Biometric;

// An android only enum to specify if you want to perform weak or strong biometric auth
public enum AuthenticatorStrength
{
    //Authentication using a Class 3 biometric, as defined on the Android compatibility definition page.
    Strong,

    //Authentication using a Class 2 biometric, as defined on the Android compatibility definition page.
    Weak
}