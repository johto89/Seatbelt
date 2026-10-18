#nullable disable
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Additional privesc check - identifies COM objects that can be hijacked via HKCU
    // Technique: if a COM CLSID exists in HKLM but NOT in HKCU, and the InProcServer32/LocalServer32
    // DLL is missing or writable, attacker can register a malicious DLL in HKCU to hijack it.
    internal class COMHijackCommand : CommandBase
    {
        public override string Command => "SharpUpCOMHijack";
        public override string Description => "[SharpUp+] Checks for COM objects vulnerable to hijacking (missing HKCU entries with writable/missing binaries)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        // Well-known CLSIDs frequently abused for persistence/privesc
        private static readonly string[] TargetCLSIDs = new[]
        {
            // Scheduled task handler COM objects
            "{0f87369f-a4e5-4cfc-bd3e-73e6154572dd}", // TaskScheduler
            "{603D3801-BD81-11d0-A3A5-00C04FD706EC}", // Shell.FolderView
            "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}", // CLSID used by explorer
            "{BCDE0395-E52F-467C-8E3D-C4579291692E}", // MMDeviceEnumerator (used by audio apps)
            "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}", // Thumbnail cache
            "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}", // ThumbnailProvider
            "{4590F811-1D3A-11D0-891F-00AA004B2E24}", // WBEM Locator
            "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}", // ShellBrowserWindow
        };

        public COMHijackCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            foreach (string clsid in TargetCLSIDs)
            {
                // Check if CLSID exists in HKLM
                string hklmPath = string.Format(@"CLSID\{0}\InprocServer32", clsid);
                RegistryKey hklmKey = Registry.ClassesRoot.OpenSubKey(hklmPath);
                if (hklmKey == null)
                {
                    // Try LocalServer32
                    hklmPath = string.Format(@"CLSID\{0}\LocalServer32", clsid);
                    hklmKey = Registry.ClassesRoot.OpenSubKey(hklmPath);
                }
                if (hklmKey == null) continue;

                string dllPath = hklmKey.GetValue("")?.ToString();
                if (string.IsNullOrEmpty(dllPath)) continue;

                // Clean up path (remove quotes, arguments)
                dllPath = dllPath.Trim('"');
                int spaceIdx = dllPath.IndexOf(' ');
                if (spaceIdx > 0 && !dllPath.StartsWith("C:\\Windows", StringComparison.OrdinalIgnoreCase))
                    dllPath = dllPath.Substring(0, spaceIdx);

                // Check if HKCU override exists
                string hkcuPath = string.Format(@"Software\Classes\CLSID\{0}", clsid);
                RegistryKey hkcuKey = Registry.CurrentUser.OpenSubKey(hkcuPath);

                bool hkcuMissing = (hkcuKey == null);
                bool dllWritable = false;
                bool dllMissing = false;

                if (!string.IsNullOrEmpty(dllPath))
                {
                    try
                    {
                        if (!System.IO.File.Exists(dllPath))
                        {
                            dllMissing = true;
                        }
                        else
                        {
                            dllWritable = SharpUpUtil.CheckModifiableAccess(dllPath);
                        }
                    }
                    catch { }
                }

                if (hkcuMissing && (dllWritable || dllMissing))
                {
                    yield return new COMHijackDTO
                    {
                        CLSID = clsid,
                        DLLPath = dllPath,
                        HKCUMissing = hkcuMissing,
                        DLLWritable = dllWritable,
                        DLLMissing = dllMissing,
                        IsVulnerable = true
                    };
                }
            }
        }

        internal class COMHijackDTO : CommandDTOBase
        {
            public string CLSID { get; set; }
            public string DLLPath { get; set; }
            public bool HKCUMissing { get; set; }
            public bool DLLWritable { get; set; }
            public bool DLLMissing { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(COMHijackDTO))]
        internal class COMHijackTextFormatter : TextFormatterBase
        {
            public COMHijackTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (COMHijackDTO)result;
                WriteLine("  [!] VULNERABLE - COM Hijack opportunity:");
                WriteLine("      CLSID: {0}", dto.CLSID);
                WriteLine("      DLL: {0}", dto.DLLPath);
                if (dto.DLLMissing) WriteLine("      Status: DLL MISSING + no HKCU override (plant DLL or register in HKCU)");
                else if (dto.DLLWritable) WriteLine("      Status: DLL WRITABLE + no HKCU override");
            }
        }
    }
}
#nullable enable
