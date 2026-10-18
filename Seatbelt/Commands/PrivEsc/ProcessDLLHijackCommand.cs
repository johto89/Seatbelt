#nullable disable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.AccessControl;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for DLL hijack opportunities in running processes
    internal class ProcessDLLHijackCommand : CommandBase
    {
        public override string Command => "SharpUpProcessDLLHijack";
        public override string Description => "[SharpUp] Checks for writable DLLs loaded by running processes (not in KnownDlls or Windows dir)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        private static readonly string RegPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDlls";

        public ProcessDLLHijackCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            // Get known DLLs from registry
            string[] keynames;
            try
            {
                var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(RegPath);
                keynames = key?.GetValueNames() ?? new string[0];
            }
            catch
            {
                keynames = new string[0];
            }

            List<string> knownDlls = new List<string>();
            foreach (string valuename in keynames)
            {
                knownDlls.Add(valuename.ToLower());
            }

            Process[] processes = Process.GetProcesses();

            foreach (Process process in processes)
            {
                try
                {
                    var processmodules = process.Modules;
                    foreach (ProcessModule module in processmodules)
                    {
                        string moduleName = module.ModuleName.ToLower();
                        string filepath = module.FileName.ToLower();
                        bool writeperms = SharpUpUtil.CheckAccess(filepath, FileSystemRights.Write);

                        if (module.FileName.EndsWith(".dll") &&
                            !knownDlls.Contains(moduleName) &&
                            !filepath.Contains("c:\\windows") &&
                            writeperms)
                        {
                            bool isProgramFiles = filepath.Contains("c:\\program files");

                            yield return new ProcessDLLHijackDTO
                            {
                                DllPath = module.FileName,
                                ProcessName = process.ProcessName,
                                ProcessId = process.Id,
                                IsProgramFiles = isProgramFiles,
                                IsVulnerable = true
                            };
                        }
                    }
                }
                catch (Exception)
                {
                    // access denied - skip
                }
            }
        }

        internal class ProcessDLLHijackDTO : CommandDTOBase
        {
            public string DllPath { get; set; }
            public string ProcessName { get; set; }
            public int ProcessId { get; set; }
            public bool IsProgramFiles { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ProcessDLLHijackDTO))]
        internal class ProcessDLLHijackTextFormatter : TextFormatterBase
        {
            public ProcessDLLHijackTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ProcessDLLHijackDTO)result;
                if (dto.IsProgramFiles)
                {
                    WriteLine("  [!] Potentially Hijackable DLL: {0}", dto.DllPath);
                    WriteLine("      (Files in Program Files may be false positives - verify manually)");
                }
                else
                {
                    WriteLine("  [!] VULNERABLE - Hijackable DLL: {0}", dto.DllPath);
                }
                WriteLine("      Process: {0} (PID: {1})", dto.ProcessName, dto.ProcessId);
            }
        }
    }
}
#nullable enable
