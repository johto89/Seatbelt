#nullable disable
using Microsoft.Win32;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks if AlwaysInstallElevated is set
    internal class AlwaysInstallElevatedCommand : CommandBase
    {
        public override string Command => "SharpUpAlwaysInstallElevated";
        public override string Description => "[SharpUp] Checks if AlwaysInstallElevated registry keys are set";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Critical;

        public AlwaysInstallElevatedCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string regPath = @"Software\Policies\Microsoft\Windows\Installer";

            string hklmValue = Runtime.GetStringValue(RegistryHive.LocalMachine, regPath, "AlwaysInstallElevated");
            string hkcuValue = Runtime.GetStringValue(RegistryHive.CurrentUser, regPath, "AlwaysInstallElevated");

            if (!string.IsNullOrEmpty(hklmValue) || !string.IsNullOrEmpty(hkcuValue))
            {
                yield return new AlwaysInstallElevatedDTO
                {
                    HKLMValue = hklmValue ?? "(not set)",
                    HKCUValue = hkcuValue ?? "(not set)",
                    IsVulnerable = true
                };
            }
            else
            {
                yield return new AlwaysInstallElevatedDTO
                {
                    HKLMValue = "(not set)",
                    HKCUValue = "(not set)",
                    IsVulnerable = false
                };
            }
        }

        internal class AlwaysInstallElevatedDTO : CommandDTOBase
        {
            public string HKLMValue { get; set; }
            public string HKCUValue { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(AlwaysInstallElevatedDTO))]
        internal class AlwaysInstallElevatedTextFormatter : TextFormatterBase
        {
            public AlwaysInstallElevatedTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (AlwaysInstallElevatedDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - AlwaysInstallElevated is set:");
                    WriteLine("      HKLM: {0}", dto.HKLMValue);
                    WriteLine("      HKCU: {0}", dto.HKCUValue);
                }
                else
                {
                    WriteLine("  [*] AlwaysInstallElevated is not set");
                }
            }
        }
    }
}
#nullable enable
