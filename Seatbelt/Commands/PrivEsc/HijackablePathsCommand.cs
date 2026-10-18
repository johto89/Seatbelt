#nullable disable
using Microsoft.Win32;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for modifiable folders in %PATH%
    internal class HijackablePathsCommand : CommandBase
    {
        public override string Command => "SharpUpHijackablePaths";
        public override string Description => "[SharpUp] Checks for modifiable folders in the system %PATH%";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public HijackablePathsCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string path = Runtime.GetStringValue(RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Path");

            if (string.IsNullOrEmpty(path))
            {
                WriteHost("  [*] System PATH not found in registry");
                yield break;
            }

            string[] pathFolders = path.Split(';');
            bool found = false;

            foreach (string folder in pathFolders)
            {
                if (string.IsNullOrEmpty(folder)) continue;

                if (SharpUpUtil.CheckModifiableAccess(folder))
                {
                    found = true;
                    yield return new HijackablePathDTO
                    {
                        ModifiablePath = folder,
                        IsVulnerable = true
                    };
                }
            }

            if (!found)
            {
                yield return new HijackablePathDTO
                {
                    ModifiablePath = "(none found)",
                    IsVulnerable = false
                };
            }
        }

        internal class HijackablePathDTO : CommandDTOBase
        {
            public string ModifiablePath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(HijackablePathDTO))]
        internal class HijackablePathTextFormatter : TextFormatterBase
        {
            public HijackablePathTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (HijackablePathDTO)result;
                if (dto.IsVulnerable)
                    WriteLine("  [!] VULNERABLE - Modifiable folder in PATH: {0}", dto.ModifiablePath);
                else
                    WriteLine("  [*] No modifiable folders found in system PATH");
            }
        }
    }
}
#nullable enable
