#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - identifies writable shared folders that may contain
    // executables, scripts or configs referenced by services/tasks
    internal class WritableSharesCommand : CommandBase
    {
        public override string Command => "SharpUpWritableShares";
        public override string Description => "[SharpUp+] Checks common shared/programdata directories for write access";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public WritableSharesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

            string[] dirsToCheck = new[]
            {
                drive + @"\ProgramData",
                drive + @"\Temp",
                drive + @"\Users\Public",
                drive + @"\Windows\Temp",
                drive + @"\Windows\Tasks",
                drive + @"\Windows\Tracing",
                drive + @"\Windows\Registration\CRMLog",
                drive + @"\Windows\System32\FxsTmp",
                drive + @"\Windows\System32\com\dmp",
                drive + @"\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
                drive + @"\Windows\System32\spool\drivers\color",
                drive + @"\Windows\System32\spool\PRINTERS",
                drive + @"\Windows\System32\Tasks",
            };

            foreach (string dir in dirsToCheck)
            {
                if (!Directory.Exists(dir)) continue;

                try
                {
                    bool writable = SharpUpUtil.CheckAccess(dir, FileSystemRights.Write);
                    bool createFiles = SharpUpUtil.CheckAccess(dir, FileSystemRights.CreateFiles);

                    if (writable || createFiles)
                    {
                        yield return new WritableShareDTO
                        {
                            Path = dir,
                            CanWrite = writable,
                            CanCreateFiles = createFiles,
                            IsVulnerable = true
                        };
                    }
                }
                catch { }
            }

            // Also check ProgramData subdirectories (often misconfigured)
            string programData = drive + @"\ProgramData";
            if (Directory.Exists(programData))
            {
                try
                {
                    foreach (string subDir in Directory.GetDirectories(programData))
                    {
                        // Skip Microsoft dirs
                        string name = Path.GetFileName(subDir);
                        if (name.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Package Cache", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            bool writable = SharpUpUtil.CheckAccess(subDir, FileSystemRights.Write);
                            if (writable)
                            {
                                // Check if there are any executables/scripts inside
                                bool hasExecutables = false;
                                try
                                {
                                    string[] exes = Directory.GetFiles(subDir, "*.exe");
                                    string[] dlls = Directory.GetFiles(subDir, "*.dll");
                                    string[] bats = Directory.GetFiles(subDir, "*.bat");
                                    string[] ps1s = Directory.GetFiles(subDir, "*.ps1");
                                    hasExecutables = (exes.Length + dlls.Length + bats.Length + ps1s.Length) > 0;
                                }
                                catch { }

                                if (hasExecutables)
                                {
                                    yield return new WritableShareDTO
                                    {
                                        Path = subDir,
                                        CanWrite = true,
                                        CanCreateFiles = true,
                                        HasExecutables = true,
                                        IsVulnerable = true
                                    };
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        internal class WritableShareDTO : CommandDTOBase
        {
            public string Path { get; set; }
            public bool CanWrite { get; set; }
            public bool CanCreateFiles { get; set; }
            public bool HasExecutables { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(WritableShareDTO))]
        internal class WritableShareTextFormatter : TextFormatterBase
        {
            public WritableShareTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (WritableShareDTO)result;
                if (dto.HasExecutables)
                {
                    WriteLine("  [!] VULNERABLE - Writable directory with executables:");
                }
                else
                {
                    WriteLine("  [!] Writable directory (DLL plant/file drop target):");
                }
                WriteLine("      Path: {0}", dto.Path);
                WriteLine("      Write: {0}, CreateFiles: {1}", dto.CanWrite, dto.CanCreateFiles);
            }
        }
    }
}
#nullable enable
