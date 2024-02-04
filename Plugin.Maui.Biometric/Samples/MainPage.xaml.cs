using Plugin.Maui.Biometric;

namespace Samples;

public partial class MainPage : ContentPage
{
    public MainPage()
    {
        InitializeComponent();
    }

    private async void OnCounterClicked(object sender, EventArgs e)
    {
        var fingerPrintService = new FingerprintService();
        var result = await fingerPrintService.GetAuthenticationStatusAsync();
        if (result == BiometricHwStatus.Success)
        {
            var data = await fingerPrintService.AuthenticateAsync(new AuthenticationRequest()
            {
                Title = "A good title",
                Subtitle="An equally good subtitle",
                Description= "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                AllowPasswordAuth = true
            });

            Console.Write(data);
        }
    }
}