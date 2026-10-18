#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - lists Volume Shadow Copies and checks if
    // SAM/SYSTEM/SECURITY hives are accessible through them
    internal class ShadowCopyCommand : CommandBase
    {
        public override string Command => "SharpUpShadowCopies";
        public override string Description => "[SharpUp+] Lists shadow copies and checks if SAM/SYSTEM/SECURITY are accessible through them";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        private static readonly string[] SensitiveHives = new[]
        {
            @"Windows\System32\config\SAM",
            @"Windows\System32\config\SYSTEM",
            @"Windows\System32\config\SECURITY",
            @"Windows\NTDS\ntds.dit"
        };

        public ShadowCopyCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            ManagementObjectSearcher wmiData = null;
            var results = new List<CommandDTOBase?>();
            try
            {
                wmiData = new ManagementObjectSearcher(@"root\cimv2",
                    "SELECT * FROM Win32_ShadowCopy");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    string deviceObj = result["DeviceObject"]?.ToString() ?? "";
                    string installDate = result["InstallDate"]?.ToString() ?? "";
                    string volumeName = result["VolumeName"]?.ToString() ?? "";

                    if (string.IsNullOrEmpty(deviceObj)) continue;

                    // Shadow copy device path format: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
                    // Access via: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\
                    string shadowPath = deviceObj + "\\";

                    var accessibleHives = new List<string>();
                    foreach (string hive in SensitiveHives)
                    {
                        string fullPath = shadowPath + hive;
                        try
                        {
                            if (File.Exists(fullPath))
                            {
                                accessibleHives.Add(hive);
                            }
                        }
                        catch { }
                    }

                    results.Add(new ShadowCopyDTO
                    {
                        DeviceObject = deviceObj,
                        InstallDate = installDate,
                        VolumeName = volumeName,
                        AccessibleHives = accessibleHives,
                        IsVulnerable = accessibleHives.Count > 0
                    });
                }
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Exception querying shadow copies: {0}", ex.Message));
            }
            finally
            {
                wmiData?.Dispose();
            }

            foreach (var r in results) yield return r;
        }

        internal class ShadowCopyDTO : CommandDTOBase
        {
            public string DeviceObject { get; set; }
            public string InstallDate { get; set; }
            public string VolumeName { get; set; }
            public List<string> AccessibleHives { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ShadowCopyDTO))]
        internal class ShadowCopyTextFormatter : TextFormatterBase
        {
            public ShadowCopyTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ShadowCopyDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - Shadow Copy with accessible sensitive hives:");
                    WriteLine("      Device: {0}", dto.DeviceObject);
                    WriteLine("      Date: {0}", dto.InstallDate);
                    foreach (string hive in dto.AccessibleHives)
                    {
                        WriteLine("      Accessible: {0}", hive);
                    }
                    WriteLine("      Extract: copy {0}\\Windows\\System32\\config\\SAM C:\\temp\\SAM", dto.DeviceObject);
                }
                else
                {
                    WriteLine("  [*] Shadow Copy found: {0} (Date: {1}) - no accessible hives", dto.DeviceObject, dto.InstallDate);
                }
            }
        }
    }
}
#nullable enable
