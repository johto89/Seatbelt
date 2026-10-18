#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for unattended install files
    internal class UnattendedInstallFilesCommand : CommandBase
    {
        public override string Command => "SharpUpUnattendedInstallFiles";
        public override string Description => "[SharpUp] Checks for unattended install files that may contain credentials";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Low;

        public UnattendedInstallFilesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string windir = Environment.GetEnvironmentVariable("windir");
            if (string.IsNullOrEmpty(windir))
            {
                WriteError("  [X] Could not determine windir");
                yield break;
            }

            string[] searchLocations = new[]
            {
                string.Format("{0}\\sysprep\\sysprep.xml", windir),
                string.Format("{0}\\sysprep\\sysprep.inf", windir),
                string.Format("{0}\\sysprep.inf", windir),
                string.Format("{0}\\Panther\\Unattended.xml", windir),
                string.Format("{0}\\Panther\\Unattend.xml", windir),
                string.Format("{0}\\Panther\\Unattend\\Unattend.xml", windir),
                string.Format("{0}\\Panther\\Unattend\\Unattended.xml", windir),
                string.Format("{0}\\System32\\Sysprep\\unattend.xml", windir),
                string.Format("{0}\\System32\\Sysprep\\Panther\\unattend.xml", windir)
            };

            bool found = false;
            foreach (string location in searchLocations)
            {
                if (File.Exists(location))
                {
                    found = true;
                    yield return new UnattendedInstallFileDTO
                    {
                        FilePath = location,
                        IsVulnerable = true
                    };
                }
            }

            if (!found)
            {
                yield return new UnattendedInstallFileDTO
                {
                    FilePath = "(none found)",
                    IsVulnerable = false
                };
            }
        }

        internal class UnattendedInstallFileDTO : CommandDTOBase
        {
            public string FilePath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(UnattendedInstallFileDTO))]
        internal class UnattendedInstallFileTextFormatter : TextFormatterBase
        {
            public UnattendedInstallFileTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (UnattendedInstallFileDTO)result;
                if (dto.IsVulnerable)
                    WriteLine("  [!] VULNERABLE - Unattended Install File found: {0}", dto.FilePath);
                else
                    WriteLine("  [*] No unattended install files found");
            }
        }
    }
}
#nullable enable
