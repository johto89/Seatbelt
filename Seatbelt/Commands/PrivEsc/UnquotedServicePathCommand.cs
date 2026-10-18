#nullable disable
using Microsoft.Win32;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for unquoted service paths
    internal class UnquotedServicePathCommand : CommandBase
    {
        public override string Command => "SharpUpUnquotedServicePath";
        public override string Description => "[SharpUp] Checks for services with unquoted paths that contain spaces";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public UnquotedServicePathCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services == null)
            {
                WriteError("  [X] Could not open services registry key");
                yield break;
            }

            foreach (string subkey in services.GetSubKeyNames())
            {
                try
                {
                    RegistryKey serviceKey = Registry.LocalMachine.OpenSubKey(
                        string.Format(@"SYSTEM\CurrentControlSet\Services\{0}", subkey));
                    if (serviceKey == null) continue;

                    string path = ((string)serviceKey.GetValue("ImagePath", "")).Trim();
                    if (string.IsNullOrEmpty(path)) continue;

                    int exeIndex = path.ToLower().IndexOf(".exe");
                    if (exeIndex < 0) continue;

                    if (!path.StartsWith("\"") &&
                        !path.StartsWith("'") &&
                        path.Substring(0, exeIndex + 4).Contains(" "))
                    {
                        string startType;
                        switch ((int)serviceKey.GetValue("Start", 0))
                        {
                            case 2: startType = "Automatic"; break;
                            case 3: startType = "Manual"; break;
                            case 4: startType = "Disabled"; break;
                            default: startType = "Unknown"; break;
                        }

                        string executablePath = path.Substring(0, exeIndex + 4);
                        int numSpaces = executablePath.Split(' ').Length - 1;
                        int lastFound = 0;

                        for (int x = 0; x < numSpaces; ++x)
                        {
                            int spaceIdx = path.ToLower().IndexOf(' ', lastFound);
                            if (spaceIdx < 0) break;
                            string newPath = path.Substring(0, spaceIdx);
                            lastFound = spaceIdx + 1;

                            int lastSlash = newPath.LastIndexOf('\\');
                            if (lastSlash < 0) continue;
                            string checkPath = newPath.Substring(0, lastSlash) + "\\";

                            if (SharpUpUtil.CheckModifiableAccess(checkPath, true))
                            {
                                yield return new UnquotedServicePathDTO
                                {
                                    ServiceName = subkey,
                                    StartMode = startType,
                                    ImagePath = path,
                                    ModifiablePath = newPath,
                                    IsVulnerable = true
                                };
                                break; // one finding per service is enough
                            }
                        }
                    }
                }
                catch
                {
                    // access denied - skip
                }
            }
        }

        internal class UnquotedServicePathDTO : CommandDTOBase
        {
            public string ServiceName { get; set; }
            public string StartMode { get; set; }
            public string ImagePath { get; set; }
            public string ModifiablePath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(UnquotedServicePathDTO))]
        internal class UnquotedServicePathTextFormatter : TextFormatterBase
        {
            public UnquotedServicePathTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (UnquotedServicePathDTO)result;
                WriteLine("  [!] VULNERABLE - Unquoted Service Path:");
                WriteLine("      Service: '{0}' (StartMode: {1})", dto.ServiceName, dto.StartMode);
                WriteLine("      Executable: '{0}'", dto.ImagePath);
                WriteLine("      Modifiable path: '{0}'", dto.ModifiablePath);
            }
        }
    }
}
#nullable enable
