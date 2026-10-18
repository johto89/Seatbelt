#nullable disable
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for registry autologon credentials
    internal class RegistryAutoLogonsCommand : CommandBase
    {
        public override string Command => "SharpUpRegistryAutoLogons";
        public override string Description => "[SharpUp] Checks for registry AutoLogon credentials";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        private static readonly string RegWinlogon = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

        public RegistryAutoLogonsCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            try
            {
                string autoAdminLogon = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "AutoAdminLogon");

                if (!string.IsNullOrEmpty(autoAdminLogon) && autoAdminLogon.Equals("1"))
                {
                    string defaultDomain = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "DefaultDomainName") ?? "";
                    string defaultUser = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "DefaultUserName") ?? "";
                    string defaultPass = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "DefaultPassword") ?? "";
                    string altDomain = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "AltDefaultDomainName") ?? "";
                    string altUser = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "AltDefaultUserName") ?? "";
                    string altPass = Runtime.GetStringValue(RegistryHive.LocalMachine, RegWinlogon, "AltDefaultPassword") ?? "";

                    if (!string.IsNullOrEmpty(defaultUser) || !string.IsNullOrEmpty(altUser))
                    {
                        yield return new RegistryAutoLogonDTO
                        {
                            DefaultDomainName = defaultDomain,
                            DefaultUserName = defaultUser,
                            DefaultPassword = defaultPass,
                            AltDefaultDomainName = altDomain,
                            AltDefaultUserName = altUser,
                            AltDefaultPassword = altPass,
                            IsVulnerable = true
                        };
                        yield break;
                    }
                }

                yield return new RegistryAutoLogonDTO { IsVulnerable = false };
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Exception: {0}", ex.Message));
            }
        }

        internal class RegistryAutoLogonDTO : CommandDTOBase
        {
            public string DefaultDomainName { get; set; }
            public string DefaultUserName { get; set; }
            public string DefaultPassword { get; set; }
            public string AltDefaultDomainName { get; set; }
            public string AltDefaultUserName { get; set; }
            public string AltDefaultPassword { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(RegistryAutoLogonDTO))]
        internal class RegistryAutoLogonTextFormatter : TextFormatterBase
        {
            public RegistryAutoLogonTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (RegistryAutoLogonDTO)result;
                if (dto.IsVulnerable)
                {
                    WriteLine("  [!] VULNERABLE - Registry AutoLogon found:");
                    WriteLine("      DefaultDomainName    : {0}", dto.DefaultDomainName);
                    WriteLine("      DefaultUserName      : {0}", dto.DefaultUserName);
                    WriteLine("      DefaultPassword      : {0}", dto.DefaultPassword);
                    WriteLine("      AltDefaultDomainName : {0}", dto.AltDefaultDomainName);
                    WriteLine("      AltDefaultUserName   : {0}", dto.AltDefaultUserName);
                    WriteLine("      AltDefaultPassword   : {0}", dto.AltDefaultPassword);
                }
                else
                {
                    WriteLine("  [*] No registry AutoLogon credentials found");
                }
            }
        }
    }
}
#nullable enable
