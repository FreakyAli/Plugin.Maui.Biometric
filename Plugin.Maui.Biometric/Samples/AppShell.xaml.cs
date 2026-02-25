namespace Samples
{
    public partial class AppShell : Shell
    {
        public AppShell()
        {
            InitializeComponent();
            Routing.RegisterRoute(nameof(BiometricPage), typeof(BiometricPage));
            Routing.RegisterRoute(nameof(SecureBiometricPage), typeof(SecureBiometricPage));
        }
    }
}
