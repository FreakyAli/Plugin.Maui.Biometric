namespace Samples
{
    public partial class HomePage : ContentPage
    {
        public HomePage()
        {
            InitializeComponent();
        }

        private async void OnBiometricClicked(object sender, EventArgs e)
        {
            await Shell.Current.GoToAsync(nameof(BiometricPage));
        }

        private async void OnSecureBiometricClicked(object sender, EventArgs e)
        {
            await Shell.Current.GoToAsync(nameof(SecureBiometricPage));
        }
    }
}
