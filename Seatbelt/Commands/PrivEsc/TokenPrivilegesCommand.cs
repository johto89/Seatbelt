#nullable disable
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Seatbelt.Interop;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for abusable token privileges
    internal class TokenPrivilegesCommand : CommandBase
    {
        public override string Command => "SharpUpTokenPrivileges";
        public override string Description => "[SharpUp] Checks for abusable token privileges (SeImpersonate, SeDebug, etc.)";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;

        private static readonly string[] SpecialPrivileges =
        {
            "SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
            "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
            "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege", "SeTcbPrivilege"
        };

        public TokenPrivilegesCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            int tokenInfLength = 0;
            IntPtr thisHandle = WindowsIdentity.GetCurrent().Token;
            SharpUpNative.GetTokenInformation(thisHandle,
                SharpUpNative.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                IntPtr.Zero, tokenInfLength, out tokenInfLength);

            IntPtr tokenInformation = Marshal.AllocHGlobal(tokenInfLength);
            try
            {
                if (SharpUpNative.GetTokenInformation(WindowsIdentity.GetCurrent().Token,
                    SharpUpNative.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    tokenInformation, tokenInfLength, out tokenInfLength))
                {
                    SharpUpNative.TOKEN_PRIVILEGES privSet =
                        (SharpUpNative.TOKEN_PRIVILEGES)Marshal.PtrToStructure(tokenInformation,
                            typeof(SharpUpNative.TOKEN_PRIVILEGES));

                    for (int index = 0; index < privSet.PrivilegeCount; index++)
                    {
                        SharpUpNative.LUID_AND_ATTRIBUTES laa = privSet.Privileges[index];
                        System.Text.StringBuilder strBuilder = new System.Text.StringBuilder();
                        int luidNameLen = 0;
                        IntPtr luidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                        try
                        {
                            Marshal.StructureToPtr(laa.Luid, luidPointer, true);
                            SharpUpNative.LookupPrivilegeName(null, luidPointer, null, ref luidNameLen);
                            strBuilder.EnsureCapacity(luidNameLen + 1);

                            if (SharpUpNative.LookupPrivilegeName(null, luidPointer, strBuilder, ref luidNameLen))
                            {
                                string privilege = strBuilder.ToString();
                                foreach (string specialPriv in SpecialPrivileges)
                                {
                                    if (privilege == specialPriv)
                                    {
                                        yield return new TokenPrivilegeDTO
                                        {
                                            Privilege = privilege,
                                            Attributes = ((SharpUpNative.LuidAttributes)laa.Attributes).ToString(),
                                            IsVulnerable = true
                                        };
                                    }
                                }
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(luidPointer);
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }

        internal class TokenPrivilegeDTO : CommandDTOBase
        {
            public string Privilege { get; set; }
            public string Attributes { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(TokenPrivilegeDTO))]
        internal class TokenPrivilegeTextFormatter : TextFormatterBase
        {
            public TokenPrivilegeTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (TokenPrivilegeDTO)result;
                WriteLine("  [!] VULNERABLE - Abusable Token Privilege: {0} ({1})", dto.Privilege, dto.Attributes);
            }
        }
    }
}
#nullable enable
