if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

var storePath = Environment.GetEnvironmentVariable("SECRETSTORE_PATH")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".secretstore");

var command = args[0].ToLowerInvariant();

if (command == "init")
{
    string password = ReadPassword();
    var store = SecretStore.Core.SecretStore.Create(storePath, password);
    store.Save();
    Console.WriteLine($"Secret store initialised at: {storePath}");
    return 0;
}

if (!File.Exists(storePath))
{
    Error($"No secret store found at '{storePath}'. Run 'secret init' first.");
    return 1;
}

try
{
    string password = ReadPassword();
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

                Console.WriteLine(value);
                return 0;
            }

        case "save":
            {
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
    Error(ex.Message);
    return 1;
}

static void Error(string message)
{
    Console.Error.WriteLine($"error: {message}");
}

static string ReadPassword()
{
    string? pwd = Environment.GetEnvironmentVariable("SECRETSTORE_PASSWORD");
    if (!string.IsNullOrEmpty(pwd))
        return pwd;

    Console.Error.Write("Master password: ");
    return ReadMasked();
}

static string ReadMasked()
{
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
            sb.Append(key.KeyChar);
        }
    }

    return sb.ToString();
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        usage: secret <command> [options]

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

