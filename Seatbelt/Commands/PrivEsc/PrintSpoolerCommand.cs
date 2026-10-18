#nullable disable
using System;
using System.Collections.Generic;
using System.ServiceProcess;
using Microsoft.Win32;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - checks if Print Spooler is running and if
    // Point and Print NoWarningNoElevationOnInstall is set (PrintNightmare / SpoolFool)
    internal class PrintSpoolerCommand : CommandBase
    {
        public override string Command => "SharpUpPrintSpooler";
        public override string Description => "[SharpUp+] Checks if Print Spooler is running and misconfigured (PrintNightmare/SpoolFool)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Low;

        public PrintSpoolerCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            // Check Spooler service status
            bool spoolerRunning = false;
            try
            {
                ServiceController sc = new ServiceController("Spooler");
                spoolerRunning = (sc.Status == ServiceControllerStatus.Running);
            }
            catch { }

            // Check Point and Print restrictions
            string ppRegPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
            string noWarning = "";
            string restrictDriver = "";

            try
            {
                RegistryKey ppKey = Registry.LocalMachine.OpenSubKey(ppRegPath);
                if (ppKey != null)
                {
                    object val = ppKey.GetValue("NoWarningNoElevationOnInstall");
                    noWarning = val?.ToString() ?? "(not set)";
                    val = ppKey.GetValue("RestrictDriverInstallationToAdministrators");
                    restrictDriver = val?.ToString() ?? "(not set)";
                }
                else
                {
                    noWarning = "(key not found)";
                    restrictDriver = "(key not found)";
                }
            }
            catch { }

            // Check if SpoolDirectory is writable or non-default
            string spoolDir = "";
            try
            {
                RegistryKey spoolerKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Print\Printers");
                if (spoolerKey != null)
                {
                    spoolDir = spoolerKey.GetValue("DefaultSpoolDirectory")?.ToString() ?? "";
                }
            }
            catch { }

            bool isVuln = spoolerRunning && (noWarning == "1" || restrictDriver == "0");

            yield return new PrintSpoolerDTO
            {
                SpoolerRunning = spoolerRunning,
                NoWarningNoElevation = noWarning,
                RestrictDriverInstall = restrictDriver,
                SpoolDirectory = spoolDir,
                IsVulnerable = isVuln
            };
        }

        internal class PrintSpoolerDTO : CommandDTOBase
        {
            public bool SpoolerRunning { get; set; }
            public string NoWarningNoElevation { get; set; }
            public string RestrictDriverInstall { get; set; }
            public string SpoolDirectory { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(PrintSpoolerDTO))]
        internal class PrintSpoolerTextFormatter : TextFormatterBase
        {
            public PrintSpoolerTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (PrintSpoolerDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - Print Spooler running with dangerous config:");
                    WriteLine("      Spooler Running: {0}", dto.SpoolerRunning);
                    WriteLine("      NoWarningNoElevationOnInstall: {0}", dto.NoWarningNoElevation);
                    WriteLine("      RestrictDriverInstallationToAdministrators: {0}", dto.RestrictDriverInstall);
                    if (!string.IsNullOrEmpty(dto.SpoolDirectory))
                        WriteLine("      Spool Directory: {0}", dto.SpoolDirectory);
                }
                else
                {
                    WriteLine("  [*] Print Spooler: Running={0}, NoWarning={1}, RestrictDriver={2}",
                        dto.SpoolerRunning, dto.NoWarningNoElevation, dto.RestrictDriverInstall);
                }
            }
        }
    }
}
#nullable enable
