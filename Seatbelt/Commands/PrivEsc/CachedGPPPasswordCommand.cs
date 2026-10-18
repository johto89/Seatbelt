#nullable disable
using System;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for cached GPP passwords
    internal class CachedGPPPasswordCommand : CommandBase
    {
        public override string Command => "SharpUpCachedGPPPassword";
        public override string Description => "[SharpUp] Checks for cached Group Policy Preference passwords";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public CachedGPPPasswordCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string allUsers = Environment.GetEnvironmentVariable("ALLUSERSPROFILE");
            if (string.IsNullOrEmpty(allUsers))
            {
                WriteError("  [X] Could not determine ALLUSERSPROFILE path");
                yield break;
            }

            try
            {
                if (!allUsers.Contains("ProgramData"))
                    allUsers += "\\Application Data";
                allUsers += "\\Microsoft\\Group Policy\\History";

                List<string> files = SharpUpUtil.FindFiles(allUsers, "*.xml");

                foreach (string file in files)
                {
                    if (!(file.Contains("Groups.xml") || file.Contains("Services.xml")
                        || file.Contains("Scheduledtasks.xml") || file.Contains("DataSources.xml")
                        || file.Contains("Printers.xml") || file.Contains("Drives.xml"))
                        || file.Contains("Registry.xml"))
                    {
                        continue;
                    }

                    if (SharpUpUtil.ParseGPPPasswordFromXml(file, out SharpUpUtil.GPPPassword result))
                    {
                        yield return new CachedGPPPasswordDTO
                        {
                            FilePath = file,
                            Details = result.ToString(),
                            IsVulnerable = true
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Exception: {0}", ex.Message));
            }
        }

        internal class CachedGPPPasswordDTO : CommandDTOBase
        {
            public string FilePath { get; set; }
            public string Details { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(CachedGPPPasswordDTO))]
        internal class CachedGPPPasswordTextFormatter : TextFormatterBase
        {
            public CachedGPPPasswordTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (CachedGPPPasswordDTO)result;
                WriteLine("  [!] VULNERABLE - Cached GPP Password found:");
                WriteLine("      File: {0}", dto.FilePath);
                WriteLine("      {0}", dto.Details);
            }
        }
    }
}
#nullable enable
