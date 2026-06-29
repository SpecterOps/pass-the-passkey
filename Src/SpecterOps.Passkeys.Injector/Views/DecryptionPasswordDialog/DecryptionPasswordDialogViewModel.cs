namespace SpecterOps.Passkeys.Injector;

public partial class DecryptionPasswordDialogViewModel : ObservableObject
{
    public string Title { get; init; } = "Enter Decryption Password";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SubmitCommand))]
    private string _password = string.Empty;

    public string ErrorMessage { get; init; } = string.Empty;

    public DecryptionPasswordDialogViewModel()
    {
    }

    public DecryptionPasswordDialogViewModel(string title, string? password, string? errorMessage)
    {
        Title = title;
        _password = password ?? string.Empty;
        ErrorMessage = errorMessage ?? string.Empty;
    }

    [RelayCommand(CanExecute = nameof(CanSubmit))]
    private void Submit(Action? onSubmit)
    {
        onSubmit?.Invoke();
    }

    private bool CanSubmit() => !string.IsNullOrEmpty(Password);
}
