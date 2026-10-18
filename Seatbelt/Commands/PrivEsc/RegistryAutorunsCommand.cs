#nullable disable
using Microsoft.Win32;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for modifiable registry autorun binaries
    internal class RegistryAutorunsCommand : CommandBase
    {
        public override string Command => "SharpUpRegistryAutoruns";
        public override string Description => "[SharpUp] Checks for modifiable binaries in registry autorun locations";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        private static readonly string[] AutorunLocations = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
        };

        public RegistryAutorunsCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            var results = new List<CommandDTOBase?>();
            foreach (string autorunLocation in AutorunLocations)
            {
                try
                {
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(autorunLocation);
                    if (key == null) continue;

                    foreach (string valueName in key.GetValueNames())
                    {
                        object val = key.GetValue(valueName);
                        if (val == null) continue;

                        Match path = Regex.Match(val.ToString(),
                            @"^\W*([a-z]:\\.+?(\.exe|\.bat|\.ps1|\.vbs))\W*", RegexOptions.IgnoreCase);
                        string binaryPath = path.Groups[1].ToString();

                        if (!string.IsNullOrEmpty(binaryPath) && SharpUpUtil.CheckModifiableAccess(binaryPath))
                        {
                            results.Add(new RegistryAutorunDTO
                            {
                                RegistryKey = "HKLM:\\" + autorunLocation,
                                BinaryPath = binaryPath,
                                IsVulnerable = true
                            });
                        }
                    }
                }
                catch
                {
                    // access denied - skip
                }
            }

            foreach (var r in results) yield return r;
        }

        internal class RegistryAutorunDTO : CommandDTOBase
        {
            public string RegistryKey { get; set; }
            public string BinaryPath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(RegistryAutorunDTO))]
        internal class RegistryAutorunTextFormatter : TextFormatterBase
        {
            public RegistryAutorunTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (RegistryAutorunDTO)result;
                WriteLine("  [!] VULNERABLE - Modifiable Registry Autorun:");
                WriteLine("      Key: {0}", dto.RegistryKey);
                WriteLine("      Binary: {0}", dto.BinaryPath);
            }
        }
    }
}
#nullable enable
