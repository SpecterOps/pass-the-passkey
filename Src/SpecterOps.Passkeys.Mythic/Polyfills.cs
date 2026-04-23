// Stand-in for the BCL type required by record/init-only property syntax on .NET Framework 4.8,
// which ships without System.Runtime.CompilerServices.IsExternalInit. The modern C# compiler
// consumes this from user code when the framework doesn't provide it.
namespace System.Runtime.CompilerServices;

internal static class IsExternalInit
{
}
