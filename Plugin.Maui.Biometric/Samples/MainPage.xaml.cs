﻿using Plugin.Maui.Biometric;

namespace Samples
{
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
            //get a list of enrolled biometric types
            var enrolledTypes = await biometric.GetEnrolledBiometricTypesAsync();
            foreach (var item in enrolledTypes)
            {
                Console.WriteLine("Biometric configured: " + item.ToString());
            }
            //get current status of the hardware
            var result = await biometric.GetAuthenticationStatusAsync();
            
            var req = new AuthenticationRequest()
            {
                Title = "A good title",
                Subtitle = "An equally good subtitle",
                NegativeText = "Cancel",
                //For Windows Hello use only "Description"
                Description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                AllowPasswordAuth = false,
            };
            // biometric authentication
            var data = await biometric.AuthenticateAsync(req,
                CancellationToken.None); // You can also pass a valid token and use it to cancel this tsak

            Console.Write(data);
        }
    }
}
