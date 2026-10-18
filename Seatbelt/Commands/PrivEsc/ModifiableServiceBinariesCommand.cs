#nullable disable
using System;
using System.Collections.Generic;
using System.Management;
using System.Text.RegularExpressions;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for modifiable service binaries
    internal class ModifiableServiceBinariesCommand : CommandBase
    {
        public override string Command => "SharpUpModifiableServiceBinaries";
        public override string Description => "[SharpUp] Checks for services with modifiable binary paths";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Critical;

        public ModifiableServiceBinariesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            ManagementObjectSearcher wmiData = null;
            var results = new List<CommandDTOBase?>();
            try
            {
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    if (result["PathName"] != null)
                    {
                        Match path = Regex.Match(result["PathName"].ToString(),
                            @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
                        string binaryPath = path.Groups[1].ToString();

                        if (SharpUpUtil.CheckModifiableAccess(binaryPath))
                        {
                            results.Add(new ModifiableServiceBinaryDTO
                            {
                                ServiceName = result["Name"]?.ToString() ?? "(unknown)",
                                State = result["State"]?.ToString() ?? "(unknown)",
                                StartMode = result["StartMode"]?.ToString() ?? "(unknown)",
                                PathName = result["PathName"]?.ToString() ?? "(unknown)",
                                IsVulnerable = true
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Exception: {0}", ex.Message));
            }
            finally
            {
                wmiData?.Dispose();
            }

            foreach (var r in results) yield return r;
        }

        internal class ModifiableServiceBinaryDTO : CommandDTOBase
        {
            public string ServiceName { get; set; }
            public string State { get; set; }
            public string StartMode { get; set; }
            public string PathName { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ModifiableServiceBinaryDTO))]
        internal class ModifiableServiceBinaryTextFormatter : TextFormatterBase
        {
            public ModifiableServiceBinaryTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ModifiableServiceBinaryDTO)result;
                WriteLine("  [!] VULNERABLE - Modifiable Service Binary:");
                WriteLine("      Service: '{0}' (State: {1}, StartMode: {2})", dto.ServiceName, dto.State, dto.StartMode);
                WriteLine("      Path: {0}", dto.PathName);
            }
        }
    }
}
#nullable enable
