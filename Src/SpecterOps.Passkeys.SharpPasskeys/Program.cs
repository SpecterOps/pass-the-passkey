
namespace SpecterOps.Passkeys.SharpPasskeys;

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
        using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat = "HH:mm:ss ";
            });
            builder.SetMinimumLevel(LogLevel.Information);
        });
        ILogger logger = loggerFactory.CreateLogger("Passkeys");

        var rootCommand = new RootCommand("SpecterOps Passkeys Mythic CLI")
        {
            PromptCommand.Create(logger),
            WaitCommand.Create(logger),
            ListCommand.Create(logger),
            HookCommand.Create(logger),
            ApiVersionCommand.Create(logger)
        };

        var config = new CommandLineConfiguration(rootCommand);
        return config.InvokeAsync(args).GetAwaiter().GetResult();
    }
}
