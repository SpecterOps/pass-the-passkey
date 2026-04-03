using System.CommandLine;

namespace SpecterOps.Passkeys.Mythic;

/// <summary>
/// Entry point for the Passkeys Mythic CLI, a tool for interacting with the Windows WebAuthn API.
/// </summary>
public class Program
{
    /// <summary>
    /// Configures and invokes the CLI with the prompt, wait, and list subcommands.
    /// </summary>
    public static int Main(string[] args)
    {
        var rootCommand = new RootCommand("SpecterOps Passkeys Mythic CLI")
        {
            PromptCommand.Create(),
            WaitCommand.Create(),
            ListCommand.Create()
        };

        var config = new CommandLineConfiguration(rootCommand);
        return config.Invoke(args);
    }
}
