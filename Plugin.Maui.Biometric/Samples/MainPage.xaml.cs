﻿using Plugin.Maui.Biometric;

namespace Samples;

public partial class MainPage : ContentPage
{
    public readonly IBiometric biometric;

    public MainPage()
    {
        InitializeComponent();
        biometric = BiometricAuthenticationService.Default;
    }

    private async void OnCounterClicked(object sender, EventArgs e)
    {
        var hwType = await biometric.GetBiometricTypeAsync();

        var result = await biometric.GetAuthenticationStatusAsync();
        if (result == BiometricHwStatus.Success)
        {
            var req = new AuthenticationRequest()
            {
                Title = "A good title",
                Subtitle = "An equally good subtitle",
                Description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                AllowPasswordAuth = true,
            };
            var data = await biometric.AuthenticateAsync(req,
                CancellationToken.None); // You can also pass a valid token and use it to cancel this tsak 

            Console.Write(data);
        }
    }
}