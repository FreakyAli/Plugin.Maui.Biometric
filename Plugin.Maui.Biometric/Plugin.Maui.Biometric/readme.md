## Installation

Add our [NuGet](https://github.com/FreakyAli/Plugin.Maui.Biometric) package or

Run the following command to add our Nuget to your .Net MAUI app:

Install-Package Plugin.Maui.Biometric -Version xx.xx.xx

Add the following permissions for Android and iOS:

`AndroidManifest.xml`

    <uses-permission android:name="android.permission.USE_BIOMETRIC" />

`Info.plist`

    <key>NSFaceIDUsageDescription</key>
    <string>Need your face to unlock! </string>

No runtime permission requests are needed and this is it you're ready to use our plugin!!

## Documentation: 

Visit our [wiki for the documentation](https://github.com/FreakyAli/Plugin.Maui.Biometric/wiki) or samples for an example usage