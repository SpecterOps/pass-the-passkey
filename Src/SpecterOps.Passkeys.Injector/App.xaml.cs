using System.ComponentModel.Design;
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
            IClipboardService clipboardService = new ClipboardService();
            IOwnerWindowService ownerWindowService = new OwnerWindowService();
            IMessageBoxService messageBoxService = new MessageBoxService(ownerWindowService);
            IPasskeyFileDialogService passkeyFileDialogService = new PasskeyFileDialogService(ownerWindowService);
            IDecryptionPasswordDialogService decryptionPasswordDialogService = new DecryptionPasswordDialogService(ownerWindowService);
            ISoftwareSigningDialogService softwareSigningDialogService =
                new SoftwareSigningDialogService(passkeyFileDialogService, decryptionPasswordDialogService, messageBoxService, ownerWindowService);
            IWebAuthnBridge webAuthnBridge = new WebAuthnBridge();
            IC2CommandsDialogService c2CommandsDialogService = new C2CommandsDialogService(ownerWindowService);
            IAssertionDialogService assertionDialogService = new AssertionDialogService(
                ownerWindowService,
                clipboardService,
                softwareSigningDialogService,
                c2CommandsDialogService);
            IAttestationDialogService attestationDialogService = new AttestationDialogService(ownerWindowService, clipboardService);
            ITokenDialogService tokenDialogService = new TokenDialogService(ownerWindowService, clipboardService);
            IMainWindowViewModel mainWindowViewModel = new MainWindowViewModel(
                webAuthnBridge,
                assertionDialogService,
                attestationDialogService,
                tokenDialogService);

            provider.AddService(typeof(IClipboardService), clipboardService);
            provider.AddService(typeof(IOwnerWindowService), ownerWindowService);
            provider.AddService(typeof(IC2CommandsDialogService), c2CommandsDialogService);
            provider.AddService(typeof(IAssertionDialogService), assertionDialogService);
            provider.AddService(typeof(IAttestationDialogService), attestationDialogService);
            provider.AddService(typeof(IMessageBoxService), messageBoxService);
            provider.AddService(typeof(IPasskeyFileDialogService), passkeyFileDialogService);
            provider.AddService(typeof(IDecryptionPasswordDialogService), decryptionPasswordDialogService);
            provider.AddService(typeof(ISoftwareSigningDialogService), softwareSigningDialogService);
            provider.AddService(typeof(ITokenDialogService), tokenDialogService);
            provider.AddService(typeof(IMainWindowViewModel), mainWindowViewModel);
            provider.AddService(typeof(IWebAuthnBridge), webAuthnBridge);
            Ioc.Default.ConfigureServices(provider);
        }
    }
}
