
namespace SpecterOps.Passkeys.SharpPasskeys;

/// <summary>
/// Entry point for the SharpPasskeys CLI, a tool for interacting with the Windows WebAuthn API.
/// </summary>
public class Program
{
    /// <summary>
    /// Configures and invokes the CLI with the prompt, WHfB, wait, list, hook, and API-version subcommands.
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

        var rootCommand = new RootCommand("SharpPasskeys CLI")
        {
            PromptCommand.Create(logger),
            WhfbCommand.Create(logger),
            WaitCommand.Create(logger),
            ListCommand.Create(logger),
            HookCommand.Create(logger),
            ApiVersionCommand.Create(logger)
        };

        var config = new CommandLineConfiguration(rootCommand);
        return config.InvokeAsync(args).GetAwaiter().GetResult();
    }
}
