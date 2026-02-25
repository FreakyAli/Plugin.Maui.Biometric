using Plugin.Maui.Biometric;

namespace Samples
{
    public partial class BiometricPage : ContentPage
    {
        private readonly IBiometric _biometric;

        public BiometricPage()
        {
            InitializeComponent();
            _biometric = BiometricAuthenticationService.Default;
        }

        private async void OnAuthenticateClicked(object sender, EventArgs e)
        {
            // Get enrolled biometric types
            var enrolledTypes = await _biometric.GetEnrolledBiometricTypesAsync();
            foreach (var item in enrolledTypes)
            {
                Console.WriteLine("Biometric configured: " + item.ToString());
            }

            // Get current hardware status
            var hwStatus = await _biometric.GetAuthenticationStatusAsync();
            Console.WriteLine("HW Status: " + hwStatus);

            var req = new AuthenticationRequest()
            {
                Title = "A good title",
                Subtitle = "An equally good subtitle",
                NegativeText = "Cancel",
                Description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                AllowPasswordAuth = false,
            };

            // You should also pass a valid token and use it to cancel biometric authentication
            var response = await this.Dispatcher.DispatchAsync(async () =>
                await _biometric.AuthenticateAsync(req, CancellationToken.None));

            StatusLabel.Text = response.Status == BiometricResponseStatus.Success
                ? $"Success ({response.AuthenticationType})"
                : $"Failed: {response.ErrorMsg}";

            Console.Write(response);
        }
    }
}
