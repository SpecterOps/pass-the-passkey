using System.Windows;

namespace SpecterOps.Passkeys.Injector;

/// <summary>
/// Resolves the WPF window that should own modal dialogs.
/// </summary>
public interface IOwnerWindowService
{
    /// <summary>
    /// Gets the active window when available, otherwise the main window.
    /// </summary>
    Window? GetOwnerWindow();
}
