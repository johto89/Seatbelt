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
    // Additional privesc check - checks if directories containing service binaries are writable
    // SharpUp only checks if the binary itself is writable, but a writable directory enables DLL planting
    internal class WritableServiceDirCommand : CommandBase
    {
        public override string Command => "SharpUpWritableServiceDir";
        public override string Description => "[SharpUp+] Checks for services whose binary directories are writable (enables DLL side-loading/planting)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public WritableServiceDirCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ManagementObjectSearcher wmiData = null;

            try
            {
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    if (result["PathName"] == null) continue;

                    Match path = Regex.Match(result["PathName"].ToString(),
                        @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase);
                    string binaryPath = path.Groups[1].ToString();
                    if (string.IsNullOrEmpty(binaryPath)) continue;

                    string dir;
                    try
                    {
                        dir = System.IO.Path.GetDirectoryName(binaryPath);
                    }
                    catch { continue; }

                    if (string.IsNullOrEmpty(dir)) continue;

                    // Skip Windows system directories
                    if (dir.StartsWith(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
                        StringComparison.OrdinalIgnoreCase)) continue;

                    if (seen.Contains(dir)) continue;
                    seen.Add(dir);

                    // Check if the binary itself is NOT writable (already covered by ModifiableServiceBinaries)
                    // but the directory IS writable - this is the gap this check fills
                    if (!SharpUpUtil.CheckModifiableAccess(binaryPath) &&
                        SharpUpUtil.CheckModifiableAccess(dir))
                    {
                        yield return new WritableServiceDirDTO
                        {
                            ServiceName = result["Name"]?.ToString() ?? "(unknown)",
                            State = result["State"]?.ToString() ?? "(unknown)",
                            StartMode = result["StartMode"]?.ToString() ?? "(unknown)",
                            BinaryPath = binaryPath,
                            WritableDir = dir,
                            IsVulnerable = true
                        };
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
        }

        internal class WritableServiceDirDTO : CommandDTOBase
        {
            public string ServiceName { get; set; }
            public string State { get; set; }
            public string StartMode { get; set; }
            public string BinaryPath { get; set; }
            public string WritableDir { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(WritableServiceDirDTO))]
        internal class WritableServiceDirTextFormatter : TextFormatterBase
        {
            public WritableServiceDirTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (WritableServiceDirDTO)result;
                WriteLine("  [!] VULNERABLE - Writable Service Directory (DLL plant possible):");
                WriteLine("      Service: '{0}' (State: {1}, StartMode: {2})", dto.ServiceName, dto.State, dto.StartMode);
                WriteLine("      Binary: {0}", dto.BinaryPath);
                WriteLine("      Writable Dir: {0}", dto.WritableDir);
            }
        }
    }
}
#nullable enable
