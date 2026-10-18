#nullable disable
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Management;
using System.ServiceProcess;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for services with modifiable registry keys
    internal class ModifiableServiceRegistryKeysCommand : CommandBase
    {
        public override string Command => "SharpUpModifiableServiceRegKeys";
        public override string Description => "[SharpUp] Checks for services with modifiable registry keys";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        public ModifiableServiceRegistryKeysCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            ServiceController[] scServices;
            try
            {
                scServices = ServiceController.GetServices();
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Could not enumerate services: {0}", ex.Message));
                yield break;
            }

            foreach (ServiceController sc in scServices)
            {
                try
                {
                    string keyPath = "SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName;
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key != null && SharpUpUtil.IsModifiableRegistryKey(key))
                    {
                        ManagementObjectSearcher wmiData = null;
                        try
                        {
                            wmiData = new ManagementObjectSearcher(@"root\cimv2",
                                string.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName));
                            ManagementObjectCollection data = wmiData.Get();

                            foreach (ManagementObject result in data)
                            {
                                yield return new ModifiableServiceRegKeyDTO
                                {
                                    ServiceName = result["Name"]?.ToString() ?? sc.ServiceName,
                                    State = result["State"]?.ToString() ?? "(unknown)",
                                    StartMode = result["StartMode"]?.ToString() ?? "(unknown)",
                                    RegistryKeyPath = keyPath,
                                    IsVulnerable = true
                                };
                            }
                        }
                        finally
                        {
                            wmiData?.Dispose();
                        }
                    }
                }
                catch (Exception)
                {
                    // access denied or other error - skip this service
                }
            }
        }

        internal class ModifiableServiceRegKeyDTO : CommandDTOBase
        {
            public string ServiceName { get; set; }
            public string State { get; set; }
            public string StartMode { get; set; }
            public string RegistryKeyPath { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ModifiableServiceRegKeyDTO))]
        internal class ModifiableServiceRegKeyTextFormatter : TextFormatterBase
        {
            public ModifiableServiceRegKeyTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ModifiableServiceRegKeyDTO)result;
                WriteLine("  [!] VULNERABLE - Modifiable Service Registry Key:");
                WriteLine("      Service: '{0}' (State: {1}, StartMode: {2})", dto.ServiceName, dto.State, dto.StartMode);
                WriteLine("      Key: HKLM\\{0}", dto.RegistryKeyPath);
            }
        }
    }
}
#nullable enable
