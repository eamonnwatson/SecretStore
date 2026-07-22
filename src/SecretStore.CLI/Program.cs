// Parse and strip any --file/-f and --password/-p flags from the arguments.
// The extracted flag values take highest priority in the resolution chain.
args = ParseFlags(args, out string? flagFile, out string? flagPassword);

// Resolve the store file path with a three-tier priority:
// 1. --file / -f flag (if provided)
// 2. SECRETSTORE_PATH environment variable
// 3. Default: ~/.secretstore
// This allows the path to be overridden at the command line, via environment
// (useful for CI/CD pipelines and container deployments), or defaulted automatically.
var storePath = flagFile
    ?? Environment.GetEnvironmentVariable("SECRETSTORE_PATH")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".secretstore");

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

var command = args[0].ToLowerInvariant();

// "init" is the only command that can run without an existing store file.
// It must be handled before the existence check below to avoid a misleading error message.
if (command == "init")
{
    string password = ReadPassword(flagPassword);
    var store = SecretStore.Core.SecretStore.Create(storePath, password);
    store.Save();
    Console.WriteLine($"Secret store initialised at: {storePath}");
    return 0;
}

// All other commands require the store to already exist.
if (!File.Exists(storePath))
{
    Error($"No secret store found at '{storePath}'. Run 'secret init' first.");
    return 1;
}

try
{
    // Decrypt the store once and hold it in memory for the duration of the command.
    // A CryptographicException here means the password was wrong or the file is corrupted.
    string password = ReadPassword(flagPassword);
    var store = SecretStore.Core.SecretStore.Open(storePath, password);

    switch (command)
    {
        case "get":
            {
                if (args.Length < 2) 
                { 
                    Error("Usage: secret get <path>"); 
                    return 1; 
                }

                var value = store.Get(args[1]);

                // Security invariant: the "get" command intentionally never prints the secret value.
                // It only confirms whether the path exists, so the command can be used safely
                // in scripts or shared terminal sessions without risk of accidental value exposure.
                if (value is null)
                {
                    Console.Error.WriteLine($"[not found] {args[1]}");
                    return 1;
                }

                Console.WriteLine($"[found] {args[1]}");
                return 0;
            }

        case "set":
            {
                if (args.Length < 3) 
                { 
                    Error("Usage: secret set <path> <value>"); 
                    return 1; 
                }

                store.Set(args[1], args[2]);
                store.Save();

                Console.WriteLine($"[set] {args[1]}");
                return 0;
            }

        case "remove":
            {
                if (args.Length < 2) 
                { 
                    Error("Usage: secret remove <path>"); 
                    return 1; 
                }

                var removed = store.Remove(args[1]);

                if (!removed) 
                { 
                    Error($"[not found] {args[1]}"); 
                    return 1; 
                }

                store.Save();

                Console.WriteLine($"[removed] {args[1]}");
                return 0;
            }

        case "list":
            {
                foreach (string p in store.List())
                    Console.WriteLine(p);

                return 0;
            }

        case "import":
            {
                if (args.Length < 2) 
                { 
                    Error("Usage: secret import <file.json>"); 
                    return 1; 
                }

                if (!File.Exists(args[1])) 
                { 
                    Error($"File not found: {args[1]}"); 
                    return 1; 
                }

                var json = File.ReadAllText(args[1]);
                store.ImportJson(json);
                store.Save();

                Console.WriteLine($"[imported] {args[1]}");
                return 0;
            }

        case "export":
            {
                // Outputs the fully decrypted secret tree as JSON to stdout.
                // The caller is responsible for redirecting this to a secure destination.
                Console.WriteLine(store.ExportJson());
                return 0;
            }

        case "print":
            {
                if (args.Length < 2)
                {
                    Error("Usage: secret print <path>");
                    return 1;
                }

                var value = store.Get(args[1]);

                if (value is null)
                {
                    Error($"[not found] {args[1]}");
                    return 1;
                }

                // Unlike "get", "print" intentionally outputs the raw secret value to stdout
                // so that it can be consumed by shell scripts (e.g. export KEY=$(secret print aws:key)).
                // Use with care in environments where stdout may be logged.
                Console.WriteLine(value);
                return 0;
            }

        case "save":
            {
                // Re-encrypts and writes the store using a fresh salt and nonce.
                // Useful after manual edits or as an explicit flush in scripted workflows.
                store.Save();
                Console.WriteLine("[saved]");
                return 0;
            }

        default:
            Error($"Unknown command: {command}");
            PrintUsage();
            return 1;
    }
}
catch (Exception ex)
{
    // Surface all unexpected errors (wrong password, corrupt file, I/O failures) through the
    // same error channel so that callers can always detect failure via a non-zero exit code.
    Error(ex.Message);
    return 1;
}

static void Error(string message)
{
    Console.Error.WriteLine($"error: {message}");
}

static string[] ParseFlags(string[] args, out string? flagFile, out string? flagPassword)
{
    // Scan the arguments for --file/-f and --password/-p, extract their values,
    // and return a new array containing only the positional arguments (command + operands).
    // This allows flags to appear anywhere in the command line while keeping the
    // existing positional-arg logic unchanged.
    flagFile = null;
    flagPassword = null;

    var positional = new List<string>();

    for (int i = 0; i < args.Length; i++)
    {
        var arg = args[i];

        if ((arg == "--file" || arg == "-f") && i + 1 < args.Length)
        {
            flagFile = args[i + 1];
            i++; // skip the value
        }
        else if ((arg == "--password" || arg == "-p") && i + 1 < args.Length)
        {
            flagPassword = args[i + 1];
            i++; // skip the value
        }
        else
        {
            positional.Add(arg);
        }
    }

    return positional.ToArray();
}

static string ReadPassword(string? flagPassword)
{
    // Resolve the master password with a three-tier priority:
    // 1. --password / -p flag (if provided)
    // 2. SECRETSTORE_PASSWORD environment variable
    // 3. Interactive masked prompt
    // This allows non-interactive use (CI pipelines, Docker containers, inline scripting)
    // while still providing a secure fallback for interactive terminal sessions where
    // the password is never echoed.
    if (!string.IsNullOrEmpty(flagPassword))
        return flagPassword;

    string? pwd = Environment.GetEnvironmentVariable("SECRETSTORE_PASSWORD");
    if (!string.IsNullOrEmpty(pwd))
        return pwd;

    Console.Error.Write("Master password: ");
    return ReadMasked();
}

static string ReadMasked()
{
    // Read the password character-by-character with intercept:true so keystrokes are not
    // echoed, then handle Backspace manually to give the user a normal editing experience.
    // Writing the newline to stderr ensures it does not appear in stdout captures.
    var sb = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.Error.WriteLine();
            break;
        }

        if (key.Key == ConsoleKey.Backspace)
        {
            if (sb.Length > 0) 
                sb.Length--;
        }
        else if (key.KeyChar != '\0')
        {
            // Ignore non-character keys (function keys, arrow keys, etc.) that produce a null char.
            sb.Append(key.KeyChar);
        }
    }

    return sb.ToString();
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        usage: secret [options] <command> [args]

        Global options:
          --file, -f <path>     Path to the store file (overrides SECRETSTORE_PATH)
          --password, -p <pwd>  Master password (overrides SECRETSTORE_PASSWORD)

        Commands:
          init                  Create a new encrypted secret store
          get <path>            Check a secret exists (value is never printed)
          set <path> <value>    Store or update a secret
          remove <path>         Delete a secret
          list                  List all secret paths
          print <path>          Print a secret value to stdout (for scripting)
          import <file.json>    Import a plaintext JSON file
          export                Output the decrypted JSON
          save                  Explicitly write the store to disk

        Environment variables:
          SECRETSTORE_PATH      Path to the store file (default: ~/.secretstore)
          SECRETSTORE_PASSWORD  Master password (avoids interactive prompt)
        """);
}


