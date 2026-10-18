#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - hunts for cleartext credentials in common config files
    internal class CredentialInFilesCommand : CommandBase
    {
        public override string Command => "SharpUpCredentialFiles";
        public override string Description => "[SharpUp+] Hunts for cleartext credentials in web.config, appsettings.json, .ini, and script files";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Medium;

        // Patterns that indicate credential presence
        private static readonly Regex[] CredPatterns = new[]
        {
            new Regex(@"(password|pwd|passwd|secret|connectionstring)\s*[=:]\s*[""']?[^\s""'<>]{3,}", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"(sa|admin|root|sysadmin)\s*[""']?\s*,\s*[""'][^""']+[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"Server\s*=.*;\s*(User\s*Id|uid)\s*=.*;\s*(Password|pwd)\s*=", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        // Target file patterns
        private static readonly string[] TargetFiles = new[]
        {
            "web.config", "app.config", "appsettings.json", "appsettings.*.json",
            "connectionStrings.config", "database.yml", "database.json",
            "*.ini", "*.conf", "wp-config.php", "config.php",
            "unattend.xml", "unattend.inf",
            "SiteList.xml", "VNC.ini", "ultravnc.ini",
            ".env", "*.env"
        };

        // Directories to search
        private static readonly string[] SearchRoots = new[]
        {
            @"C:\inetpub",
            @"C:\xampp",
            @"C:\wamp",
            @"C:\Sites",
            @"C:\WebSites",
        };

        public CredentialInFilesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

            var searchDirs = new List<string>(SearchRoots);
            searchDirs.Add(drive + @"\inetpub");
            searchDirs.Add(drive + @"\ProgramData");
            searchDirs.Add(drive + @"\Program Files");
            searchDirs.Add(drive + @"\Program Files (x86)");

            // Also check user profiles for script files
            string usersDir = drive + @"\Users";
            if (Directory.Exists(usersDir))
            {
                try
                {
                    foreach (string userDir in Directory.GetDirectories(usersDir))
                    {
                        string desktop = Path.Combine(userDir, "Desktop");
                        string documents = Path.Combine(userDir, "Documents");
                        if (Directory.Exists(desktop)) searchDirs.Add(desktop);
                        if (Directory.Exists(documents)) searchDirs.Add(documents);
                    }
                }
                catch { }
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var credResults = new List<CommandDTOBase?>();

            foreach (string root in searchDirs)
            {
                if (!Directory.Exists(root)) continue;

                foreach (string pattern in TargetFiles)
                {
                    List<string> files;
                    try
                    {
                        files = RecursiveFindFiles(root, pattern, 4); // max depth 4
                    }
                    catch { continue; }

                    foreach (string file in files)
                    {
                        if (seen.Contains(file)) continue;
                        seen.Add(file);

                        try
                        {
                            string content = File.ReadAllText(file);
                            foreach (Regex rx in CredPatterns)
                            {
                                Match m = rx.Match(content);
                                if (m.Success)
                                {
                                    // Truncate the match for display
                                    string snippet = m.Value;
                                    if (snippet.Length > 120) snippet = snippet.Substring(0, 120) + "...";

                                    credResults.Add(new CredentialFileDTO
                                    {
                                        FilePath = file,
                                        MatchSnippet = snippet,
                                        IsVulnerable = true
                                    });
                                    break; // one match per file is enough
                                }
                            }
                        }
                        catch { }
                    }
                }
            }

            foreach (var r in credResults) yield return r;
        }

        private static List<string> RecursiveFindFiles(string path, string pattern, int maxDepth)
        {
            var result = new List<string>();
            RecursiveFindFilesHelper(path, pattern, maxDepth, 0, result);
            return result;
        }

        private static void RecursiveFindFilesHelper(string path, string pattern, int maxDepth, int currentDepth, List<string> result)
        {
            if (currentDepth > maxDepth) return;
            try
            {
                result.AddRange(Directory.GetFiles(path, pattern));
                foreach (string dir in Directory.GetDirectories(path))
                {
                    RecursiveFindFilesHelper(dir, pattern, maxDepth, currentDepth + 1, result);
                }
            }
            catch { }
        }

        internal class CredentialFileDTO : CommandDTOBase
        {
            public string FilePath { get; set; }
            public string MatchSnippet { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(CredentialFileDTO))]
        internal class CredentialFileTextFormatter : TextFormatterBase
        {
            public CredentialFileTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (CredentialFileDTO)result;
                WriteLine("  [!] VULNERABLE - Possible credentials in config file:");
                WriteLine("      File: {0}", dto.FilePath);
                WriteLine("      Match: {0}", dto.MatchSnippet);
            }
        }
    }
}
#nullable enable
