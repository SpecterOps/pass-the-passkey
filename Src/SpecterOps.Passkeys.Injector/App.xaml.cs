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
            var webAuthnBridge = new WebAuthnBridge();
            var assertionViewModel = new AssertionDialogViewModel();
            var tokenDialogViewModel = new TokenDialogViewModel();
            var mainWindowViewModel = new MainWindowViewModel(assertionViewModel, tokenDialogViewModel, webAuthnBridge);

            provider.AddService(typeof(AssertionDialogViewModel), assertionViewModel);
            provider.AddService(typeof(TokenDialogViewModel), tokenDialogViewModel);
            provider.AddService(typeof(MainWindowViewModel), mainWindowViewModel);
            provider.AddService(typeof(WebAuthnBridge), webAuthnBridge);
            Ioc.Default.ConfigureServices(provider);
        }
    }
}
