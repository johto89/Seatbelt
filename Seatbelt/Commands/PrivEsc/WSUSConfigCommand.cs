#nullable disable
using Microsoft.Win32;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - checks if WSUS uses HTTP (vulnerable to MITM injection)
    // Reference: WSUSPect, SharpWSUS
    internal class WSUSConfigCommand : CommandBase
    {
        public override string Command => "SharpUpWSUSConfig";
        public override string Description => "[SharpUp+] Checks if WSUS is configured over HTTP (vulnerable to update injection via MITM)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Low;

        public WSUSConfigCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string regPath = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";

            RegistryKey wuKey = Registry.LocalMachine.OpenSubKey(regPath);
            if (wuKey == null)
            {
                yield return new WSUSConfigDTO
                {
                    WUServer = "(WSUS not configured via GPO)",
                    IsVulnerable = false
                };
                yield break;
            }

            string wuServer = wuKey.GetValue("WUServer")?.ToString() ?? "";
            string wuStatusServer = wuKey.GetValue("WUStatusServer")?.ToString() ?? "";
            object useWUServer = wuKey.GetValue("UseWUServer");
            string useWU = useWUServer?.ToString() ?? "0";

            bool isHttp = false;
            if (!string.IsNullOrEmpty(wuServer))
            {
                isHttp = wuServer.StartsWith("http://", System.StringComparison.OrdinalIgnoreCase);
            }

            yield return new WSUSConfigDTO
            {
                WUServer = string.IsNullOrEmpty(wuServer) ? "(not set)" : wuServer,
                WUStatusServer = string.IsNullOrEmpty(wuStatusServer) ? "(not set)" : wuStatusServer,
                UseWUServer = useWU,
                IsHTTP = isHttp,
                IsVulnerable = isHttp && useWU == "1"
            };
        }

        internal class WSUSConfigDTO : CommandDTOBase
        {
            public string WUServer { get; set; }
            public string WUStatusServer { get; set; }
            public string UseWUServer { get; set; }
            public bool IsHTTP { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(WSUSConfigDTO))]
        internal class WSUSConfigTextFormatter : TextFormatterBase
        {
            public WSUSConfigTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (WSUSConfigDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - WSUS configured over HTTP (SharpWSUS/WSUSPect attack possible):");
                    WriteLine("      WUServer: {0}", dto.WUServer);
                    WriteLine("      WUStatusServer: {0}", dto.WUStatusServer);
                    WriteLine("      UseWUServer: {0}", dto.UseWUServer);
                }
                else
                {
                    WriteLine("  [*] WSUS: {0} (UseWUServer: {1})", dto.WUServer, dto.UseWUServer);
                }
            }
        }
    }
}
#nullable enable
