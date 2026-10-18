#nullable disable
using System;
using System.Collections.Generic;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Seatbelt.Interop;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for services with modifiable DACL
    internal class ModifiableServicesCommand : CommandBase
    {
        public override string Command => "SharpUpModifiableServices";
        public override string Description => "[SharpUp] Checks for services the current user can modify (change config, write DAC, etc.)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.Critical;

        public ModifiableServicesCommand(Runtime runtime) : base(runtime) { }

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

            var getServiceHandle = typeof(ServiceController).GetMethod("GetServiceHandle",
                BindingFlags.Instance | BindingFlags.NonPublic);

            object[] readRights = { 0x00020000 };

            SharpUpNative.ServiceAccessRights[] modifyRights =
            {
                SharpUpNative.ServiceAccessRights.ChangeConfig,
                SharpUpNative.ServiceAccessRights.WriteDac,
                SharpUpNative.ServiceAccessRights.WriteOwner,
                SharpUpNative.ServiceAccessRights.GenericAll,
                SharpUpNative.ServiceAccessRights.GenericWrite,
                SharpUpNative.ServiceAccessRights.AllAccess
            };

            var results = new List<CommandDTOBase?>();
            foreach (ServiceController sc in scServices)
            {
                try
                {
                    IntPtr handle = (IntPtr)getServiceHandle.Invoke(sc, readRights);
                    byte[] psd = new byte[0];
                    uint bufSizeNeeded;
                    bool ok = SharpUpNative.QueryServiceObjectSecurity(handle,
                        SecurityInfos.DiscretionaryAcl, psd, 0, out bufSizeNeeded);

                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 122 || err == 0)
                        {
                            psd = new byte[bufSizeNeeded];
                            ok = SharpUpNative.QueryServiceObjectSecurity(handle,
                                SecurityInfos.DiscretionaryAcl, psd, bufSizeNeeded, out bufSizeNeeded);
                        }
                        else
                        {
                            continue;
                        }
                    }
                    if (!ok) continue;

                    RawSecurityDescriptor rsd = new RawSecurityDescriptor(psd, 0);
                    RawAcl racl = rsd.DiscretionaryAcl;
                    DiscretionaryAcl dacl = new DiscretionaryAcl(false, false, racl);

                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (CommonAce ace in dacl)
                    {
                        if ((identity.Groups.Contains(ace.SecurityIdentifier) ||
                             ace.SecurityIdentifier == identity.User) &&
                            ace.AceType == AceType.AccessAllowed)
                        {
                            SharpUpNative.ServiceAccessRights serviceRights =
                                (SharpUpNative.ServiceAccessRights)ace.AccessMask;

                            foreach (var modifyRight in modifyRights)
                            {
                                if ((modifyRight & serviceRights) == modifyRight)
                                {
                                    ManagementObjectSearcher wmiData = null;
                                    try
                                    {
                                        wmiData = new ManagementObjectSearcher(@"root\cimv2",
                                            string.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'",
                                                sc.ServiceName));
                                        ManagementObjectCollection data = wmiData.Get();

                                        foreach (ManagementObject result in data)
                                        {
                                            results.Add(new ModifiableServiceDTO
                                            {
                                                ServiceName = result["Name"]?.ToString() ?? sc.ServiceName,
                                                State = result["State"]?.ToString() ?? "(unknown)",
                                                StartMode = result["StartMode"]?.ToString() ?? "(unknown)",
                                                IsVulnerable = true
                                            });
                                        }
                                    }
                                    finally
                                    {
                                        wmiData?.Dispose();
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // access denied or other error - skip
                }
            }

            foreach (var r in results) yield return r;
        }

        internal class ModifiableServiceDTO : CommandDTOBase
        {
            public string ServiceName { get; set; }
            public string State { get; set; }
            public string StartMode { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ModifiableServiceDTO))]
        internal class ModifiableServiceTextFormatter : TextFormatterBase
        {
            public ModifiableServiceTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ModifiableServiceDTO)result;
                WriteLine("  [!] VULNERABLE - Modifiable Service DACL:");
                WriteLine("      Service: '{0}' (State: {1}, StartMode: {2})", dto.ServiceName, dto.State, dto.StartMode);
            }
        }
    }
}
#nullable enable
