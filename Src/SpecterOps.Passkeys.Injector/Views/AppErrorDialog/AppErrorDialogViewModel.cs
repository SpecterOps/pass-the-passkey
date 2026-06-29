using CommunityToolkit.Mvvm.ComponentModel;

namespace SpecterOps.Passkeys.Injector;

public partial class AppErrorDialogViewModel : ObservableObject
{
    [ObservableProperty]
    private string _title = "Error";

    [ObservableProperty]
    private string _message = "An unexpected error occurred.";
}
