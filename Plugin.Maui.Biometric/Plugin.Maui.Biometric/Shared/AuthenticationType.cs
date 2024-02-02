namespace Plugin.Maui.Biometric;

public enum AuthenticationType
{
	None = 0,
	FaceId = 1,
	Fingerprint = 2
}

public enum BiometricStatus
{
	Success,
	Failure,
	NoHardware,
	Unavailable,
	NotEnrolled,
	LockedOut,
	Cancelled
}