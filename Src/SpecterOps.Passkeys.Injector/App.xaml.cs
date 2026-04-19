using System.ComponentModel.Design;
using System.Windows;
using CommunityToolkit.Mvvm.DependencyInjection;

namespace SpecterOps.Passkeys.Injector
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            ConfigureServices();
            InitializeComponent();
        }

        /// <summary>
        /// Configures the services for the application.
        /// </summary>
        private static void ConfigureServices()
        {
            var provider = new ServiceContainer();
            IWebAuthnBridge webAuthnBridge = new WebAuthnBridge();
            IAssertionDialogViewModel assertionViewModel = new AssertionDialogViewModel();
            IAttestationDialogViewModel attestationViewModel = new AttestationDialogViewModel();
            ITokenDialogViewModel tokenDialogViewModel = new TokenDialogViewModel();
            IMainWindowViewModel mainWindowViewModel = new MainWindowViewModel(assertionViewModel, attestationViewModel, tokenDialogViewModel, webAuthnBridge);

            provider.AddService(typeof(IAssertionDialogViewModel), assertionViewModel);
            provider.AddService(typeof(IAttestationDialogViewModel), attestationViewModel);
            provider.AddService(typeof(ITokenDialogViewModel), tokenDialogViewModel);
            provider.AddService(typeof(IMainWindowViewModel), mainWindowViewModel);
            provider.AddService(typeof(IWebAuthnBridge), webAuthnBridge);
            Ioc.Default.ConfigureServices(provider);
        }
    }
}
