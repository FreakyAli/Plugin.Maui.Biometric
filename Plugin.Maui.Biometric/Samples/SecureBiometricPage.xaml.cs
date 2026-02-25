using Plugin.Maui.Biometric;

namespace Samples
{
    public partial class SecureBiometricPage : ContentPage
    {
        private const string KeyId = "sample-aes-key";
        private static readonly byte[] PlainText = System.Text.Encoding.UTF8.GetBytes("Hello, Secure World!");

        private readonly ISecureBiometric _secureBiometric;
        private byte[]? _encryptedData;
        private byte[]? _iv;

        public SecureBiometricPage()
        {
            InitializeComponent();
            _secureBiometric = SecureBiometricAuthenticationService.Default;
        }

        private async void OnCreateKeyClicked(object sender, EventArgs e)
        {
            var options = new CryptoKeyOptions
            {
                Algorithm = KeyAlgorithm.Aes,
                KeySize = 256,
                BlockMode = BlockMode.Gcm,
                Padding = Padding.None,
                Operation = CryptoOperation.Encrypt | CryptoOperation.Decrypt,
                RequireUserAuthentication = true,
            };

            var result = await _secureBiometric.CreateKeyAsync(KeyId, options);

            ResultLabel.Text = result.WasSuccessful
                ? $"Key created\n{result.AdditionalInfo}"
                : $"Create failed: {result.ErrorMessage}";

            Console.WriteLine(ResultLabel.Text);
        }

        private async void OnEncryptClicked(object sender, EventArgs e)
        {
            var request = new SecureAuthenticationRequest
            {
                KeyId = KeyId,
                InputData = PlainText,
                Algorithm = KeyAlgorithm.Aes,
                BlockMode = BlockMode.Gcm,
                Padding = Padding.None,
                Title = "Encrypt",
                Subtitle = "Authenticate to encrypt data",
                NegativeText = "Cancel",
            };

            // You should also pass a valid token and use it to cancel biometric authentication
            var response = await this.Dispatcher.DispatchAsync(async () =>
                await _secureBiometric.EncryptAsync(request, CancellationToken.None));

            if (response.WasSuccessful)
            {
                _encryptedData = response.OutputData;
                _iv = response.IV;
                ResultLabel.Text = $"Encrypted:\n{Convert.ToBase64String(_encryptedData!)}";
            }
            else
            {
                ResultLabel.Text = $"Encrypt failed: {response.ErrorMessage}";
            }

            Console.WriteLine(ResultLabel.Text);
        }

        private async void OnDecryptClicked(object sender, EventArgs e)
        {
            if (_encryptedData is null || _iv is null)
            {
                ResultLabel.Text = "Nothing to decrypt — run Encrypt first";
                return;
            }

            var request = new SecureAuthenticationRequest
            {
                KeyId = KeyId,
                InputData = _encryptedData,
                IV = _iv,
                Algorithm = KeyAlgorithm.Aes,
                BlockMode = BlockMode.Gcm,
                Padding = Padding.None,
                Title = "Decrypt",
                Subtitle = "Authenticate to decrypt data",
                NegativeText = "Cancel",
            };

            // You should also pass a valid token and use it to cancel biometric authentication
            var response = await this.Dispatcher.DispatchAsync(async () =>
                await _secureBiometric.DecryptAsync(request, CancellationToken.None));

            if (response.WasSuccessful)
            {
                var plainText = System.Text.Encoding.UTF8.GetString(response.OutputData!);
                ResultLabel.Text = $"Decrypted: {plainText}";
            }
            else
            {
                ResultLabel.Text = $"Decrypt failed: {response.ErrorMessage}";
            }

            Console.WriteLine(ResultLabel.Text);
        }

        private async void OnDeleteKeyClicked(object sender, EventArgs e)
        {
            var result = await _secureBiometric.DeleteKeyAsync(KeyId);

            _encryptedData = null;
            _iv = null;

            ResultLabel.Text = result.WasSuccessful
                ? "Key deleted"
                : $"Delete failed: {result.ErrorMessage}";

            Console.WriteLine(ResultLabel.Text);
        }
    }
}
