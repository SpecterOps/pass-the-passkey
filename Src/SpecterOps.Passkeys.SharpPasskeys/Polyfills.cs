namespace System.Runtime.CompilerServices
{
    // Stand-in for the BCL type required by record/init-only property syntax on .NET Framework 4.8,
    // which ships without System.Runtime.CompilerServices.IsExternalInit. The modern C# compiler
    // consumes this from user code when the framework doesn't provide it.
    internal static class IsExternalInit
    {
    }
}

namespace System.Diagnostics.CodeAnalysis
{
    [global::System.AttributeUsage(global::System.AttributeTargets.Parameter, Inherited = false)]
    internal sealed class NotNullWhenAttribute : global::System.Attribute
    {
        public NotNullWhenAttribute(bool returnValue)
        {
            ReturnValue = returnValue;
        }

        public bool ReturnValue { get; }
    }
}
