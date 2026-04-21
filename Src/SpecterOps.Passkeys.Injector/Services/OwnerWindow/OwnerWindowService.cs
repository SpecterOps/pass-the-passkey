using System.Linq;
using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Default resolver for modal dialog owner windows.
/// </summary>
public sealed class OwnerWindowService : IOwnerWindowService
{
    /// <inheritdoc/>
    public Window? GetOwnerWindow()
    {
        return Application.Current?.Windows
            .OfType<Window>()
            .FirstOrDefault(static window => window.IsActive)
            ?? Application.Current?.MainWindow;
    }
}
