namespace Plugin.Maui.Biometric;

/// <summary>
/// This enum gives you an idea of
/// what the current status is for your hardware/device.
/// </summary>
public enum BiometricHwStatus
{
    NoHardware,
    Unavailable,
    Unsupported,
    NotEnrolled,
    LockedOut,
    Success,
    Failure,
    PresentButNotEnrolled
}