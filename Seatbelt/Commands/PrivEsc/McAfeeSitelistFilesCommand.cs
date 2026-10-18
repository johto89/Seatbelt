#nullable disable
using System;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - finds McAfee SiteList.xml files
    internal class McAfeeSitelistFilesCommand : CommandBase
    {
        public override string Command => "SharpUpMcAfeeSitelistFiles";
        public override string Description => "[SharpUp] Checks for McAfee SiteList.xml files containing credentials";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public McAfeeSitelistFilesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string drive = Environment.GetEnvironmentVariable("SystemDrive");
            if (string.IsNullOrEmpty(drive)) drive = "C:";

            string[] searchLocations = new[]
            {
                string.Format("{0}\\Program Files\\", drive),
                string.Format("{0}\\Program Files (x86)\\", drive),
                string.Format("{0}\\Documents and Settings\\", drive),
                string.Format("{0}\\Users\\", drive)
            };

            bool found = false;
            foreach (string location in searchLocations)
            {
                try
                {
                    List<string> files = SharpUpUtil.FindFiles(location, "SiteList.xml");
                    foreach (string file in files)
                    {
                        found = true;
                        yield return new McAfeeSitelistDTO
                        {
                            FilePath = file,
                            IsVulnerable = true
                        };
                    }
                }
                catch (Exception)
                {
                    // access denied to search location - skip
                }
            }

            if (!found)
            {
                yield return new McAfeeSitelistDTO
                {
                    FilePath = "(none found)",
                    IsVulnerable = false
                };
            }
        }

        internal class McAfeeSitelistDTO : CommandDTOBase
        {
            public string FilePath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(McAfeeSitelistDTO))]
        internal class McAfeeSitelistTextFormatter : TextFormatterBase
        {
            public McAfeeSitelistTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (McAfeeSitelistDTO)result;
                if (dto.IsVulnerable)
                    WriteLine("  [!] VULNERABLE - McAfee SiteList.xml found: {0}", dto.FilePath);
                else
                    WriteLine("  [*] No McAfee SiteList.xml files found");
            }
        }
    }
}
#nullable enable
