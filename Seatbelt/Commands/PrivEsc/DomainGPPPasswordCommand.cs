#nullable disable
using System;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for GPP passwords in SYSVOL
    internal class DomainGPPPasswordCommand : CommandBase
    {
        public override string Command => "SharpUpDomainGPPPassword";
        public override string Description => "[SharpUp] Checks for GPP passwords in domain SYSVOL";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public DomainGPPPasswordCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string dnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");

            if (string.IsNullOrEmpty(dnsDomain) || dnsDomain.Length <= 1)
            {
                yield return new DomainGPPPasswordDTO
                {
                    Details = "Machine is not a domain member or User is not a member of the domain.",
                    IsVulnerable = false
                };
                yield break;
            }

            try
            {
                List<string> files = SharpUpUtil.FindFiles("\\\\" + dnsDomain + "\\SYSVOL", "*.xml");

                foreach (string file in files)
                {
                    if (file.Contains("Registry.xml") || file.Contains("Groups.xml") ||
                        file.Contains("Services.xml") || file.Contains("ScheduledTasks.xml") ||
                        file.Contains("DataSources.xml") || file.Contains("Printers.xml") ||
                        file.Contains("Drives.xml"))
                    {
                        if (SharpUpUtil.ParseGPPPasswordFromXml(file, out SharpUpUtil.GPPPassword result))
                        {
                            yield return new DomainGPPPasswordDTO
                            {
                                FilePath = file,
                                Details = result.ToString(),
                                IsVulnerable = true
                            };
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Exception: {0}", ex.Message));
            }
        }

        internal class DomainGPPPasswordDTO : CommandDTOBase
        {
            public string FilePath { get; set; }
            public string Details { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(DomainGPPPasswordDTO))]
        internal class DomainGPPPasswordTextFormatter : TextFormatterBase
        {
            public DomainGPPPasswordTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (DomainGPPPasswordDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - GPP Password found in SYSVOL:");
                    WriteLine("      File: {0}", dto.FilePath);
                    WriteLine("      {0}", dto.Details);
                }
                else
                {
                    WriteLine("  [*] {0}", dto.Details);
                }
            }
        }
    }
}
#nullable enable
