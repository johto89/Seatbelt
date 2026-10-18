using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Xml;

namespace Seatbelt.Util
{
    // Utilities ported from GhostPack/SharpUp
    internal static class SharpUpUtil
    {
        internal struct GPPPassword
        {
            public string UserName;
            public string NewName;
            public string cPassword;
            public string Changed;

            public override string ToString()
            {
                string _uname = string.IsNullOrEmpty(UserName) ? "[BLANK]" : UserName;
                string _newname = string.IsNullOrEmpty(NewName) ? "[BLANK]" : NewName;
                string _cp = string.IsNullOrEmpty(cPassword) ? "[BLANK]" : cPassword;
                string _changed = string.IsNullOrEmpty(Changed) ? "[BLANK]" : Changed;

                if (!string.IsNullOrEmpty(cPassword))
                {
                    try { _cp = DecryptGPPPassword(cPassword); } catch { }
                }

                return string.Format("UserName: {0} | NewName: {1} | cPassword: {2} | Changed: {3}",
                    _uname, _newname, _cp, _changed);
            }
        }

        internal static bool ParseGPPPasswordFromXml(string filePath, out GPPPassword result)
        {
            result = new GPPPassword();
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);
            if (!xmlDoc.InnerXml.Contains("cpassword"))
                return false;

            if (filePath.Contains("Groups.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/Groups/User/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Groups/User");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("userName")) result.UserName = attr.Value;
                        if (attr.Name.Equals("newName")) result.NewName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Services.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/NTServices/NTService/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/NTServices/NTService");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("accountName")) result.UserName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Scheduledtasks.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/ScheduledTasks/Task/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/ScheduledTasks/Task");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("runAs")) result.UserName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("DataSources.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/DataSources/DataSource/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/DataSources/DataSource");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("username")) result.UserName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Printers.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/Printers/SharedPrinter/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Printers/SharedPrinter");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("username")) result.UserName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Drives.xml"))
            {
                XmlNode a = xmlDoc.SelectSingleNode("/Drives/Drive/Properties");
                XmlNode b = xmlDoc.SelectSingleNode("/Drives/Drive");
                if (a != null)
                {
                    foreach (XmlAttribute attr in a.Attributes)
                    {
                        if (attr.Name.Equals("cpassword")) result.cPassword = attr.Value;
                        if (attr.Name.Equals("username")) result.UserName = attr.Value;
                    }
                }
                if (b != null)
                {
                    foreach (XmlAttribute attr in b.Attributes)
                    {
                        if (attr.Name.Equals("changed")) result.Changed = attr.Value;
                    }
                }
            }
            else if (filePath.Contains("Registry.xml"))
            {
                XmlNodeList a = xmlDoc.GetElementsByTagName("Properties");
                foreach (XmlNode b in a)
                {
                    if (b.Name.Equals("DefaultPassword"))
                        result.cPassword += "," + b.Value;
                    if (b.Name.Equals("DefaultUsername"))
                        result.UserName += "," + b.Value;
                }
            }
            else
            {
                return false;
            }
            return true;
        }

        internal static string DecryptGPPPassword(string cpassword)
        {
            int mod = cpassword.Length % 4;
            switch (mod)
            {
                case 1:
                    cpassword = cpassword.Substring(0, cpassword.Length - 1);
                    break;
                case 2:
                case 3:
                    cpassword += "".PadLeft(4 - mod, '=');
                    break;
            }

            byte[] base64decoded = Convert.FromBase64String(cpassword);
            AesCryptoServiceProvider aesObject = new AesCryptoServiceProvider();
            byte[] aesKey = { 0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
                              0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
                              0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
                              0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b };
            byte[] aesIV = new byte[aesObject.IV.Length];
            aesObject.IV = aesIV;
            aesObject.Key = aesKey;
            ICryptoTransform aesDecryptor = aesObject.CreateDecryptor();
            byte[] outBlock = aesDecryptor.TransformFinalBlock(base64decoded, 0, base64decoded.Length);
            return System.Text.UnicodeEncoding.Unicode.GetString(outBlock);
        }

        internal static bool CheckAccess(string path, FileSystemRights accessRight)
        {
            if (string.IsNullOrEmpty(path)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(path)
                    .GetAccessRules(true, true, typeof(SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);

                foreach (FileSystemAccessRule rule in rules)
                {
                    var ruleNtAccount = rule.IdentityReference.Translate(typeof(NTAccount));
                    if (identity.Groups.Contains(rule.IdentityReference) ||
                        principal.IsInRole(ruleNtAccount.Value) ||
                        ruleNtAccount.Value == identity.Name)
                    {
                        if ((accessRight & rule.FileSystemRights) == accessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }

            return false;
        }

        internal static List<string> FindFiles(string path, string patterns)
        {
            var files = new List<string>();
            try
            {
                foreach (string pattern in patterns.Split(';'))
                {
                    files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
                }
                foreach (var directory in Directory.GetDirectories(path))
                    files.AddRange(FindFiles(directory, patterns));
            }
            catch (UnauthorizedAccessException) { }
            catch (PathTooLongException) { }
            return files;
        }

        internal static bool CheckModifiableAccess(string path, bool fileRightsOnly = false)
        {
            if (string.IsNullOrEmpty(path)) return false;

            FileSystemRights[] modifyRights = fileRightsOnly
                ? new FileSystemRights[] {
                    FileSystemRights.FullControl,
                    FileSystemRights.Modify,
                    FileSystemRights.TakeOwnership,
                    FileSystemRights.Write,
                    FileSystemRights.WriteData,
                    FileSystemRights.CreateFiles
                }
                : new FileSystemRights[] {
                    FileSystemRights.ChangePermissions,
                    FileSystemRights.FullControl,
                    FileSystemRights.Modify,
                    FileSystemRights.TakeOwnership,
                    FileSystemRights.Write,
                    FileSystemRights.WriteData,
                    FileSystemRights.CreateDirectories,
                    FileSystemRights.CreateFiles
                };

            ArrayList paths = new ArrayList();
            paths.Add(path);

            try
            {
                FileAttributes attr = File.GetAttributes(path);
                if ((attr & FileAttributes.Directory) != FileAttributes.Directory)
                {
                    string parentFolder = Path.GetDirectoryName(path);
                    paths.Add(parentFolder);
                }
            }
            catch { return false; }

            try
            {
                foreach (string candidatePath in paths)
                {
                    AuthorizationRuleCollection rules = Directory.GetAccessControl(candidatePath)
                        .GetAccessRules(true, true, typeof(SecurityIdentifier));
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();

                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (identity.Groups.Contains(rule.IdentityReference) ||
                            rule.IdentityReference == identity.User)
                        {
                            foreach (FileSystemRights accessRight in modifyRights)
                            {
                                if ((accessRight & rule.FileSystemRights) == accessRight)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                        return true;
                                }
                            }
                        }
                    }
                }
                return false;
            }
            catch { return false; }
        }

        internal static bool IsHighIntegrity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        internal static bool IsLocalAdmin()
        {
            string[]? sids = GetTokenGroupSIDs();
            if (sids == null) return false;
            foreach (string sid in sids)
            {
                if (sid == "S-1-5-32-544") return true;
            }
            return false;
        }

        internal static string[]? GetTokenGroupSIDs()
        {
            int tokenInfLength = 0;
            bool result = Interop.SharpUpNative.GetTokenInformation(
                WindowsIdentity.GetCurrent().Token,
                Interop.SharpUpNative.TOKEN_INFORMATION_CLASS.TokenGroups,
                IntPtr.Zero, tokenInfLength, out tokenInfLength);

            IntPtr tokenInformation = System.Runtime.InteropServices.Marshal.AllocHGlobal(tokenInfLength);
            result = Interop.SharpUpNative.GetTokenInformation(
                WindowsIdentity.GetCurrent().Token,
                Interop.SharpUpNative.TOKEN_INFORMATION_CLASS.TokenGroups,
                tokenInformation, tokenInfLength, out tokenInfLength);

            if (!result)
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(tokenInformation);
                return null;
            }

            var groups = (Interop.SharpUpNative.TOKEN_GROUPS)System.Runtime.InteropServices.Marshal.PtrToStructure(
                tokenInformation, typeof(Interop.SharpUpNative.TOKEN_GROUPS));
            string[] userSIDs = new string[groups.GroupCount];
            int sidAndAttrSize = System.Runtime.InteropServices.Marshal.SizeOf(new Interop.SharpUpNative.SID_AND_ATTRIBUTES());

            for (int i = 0; i < groups.GroupCount; i++)
            {
                var sidAndAttributes = (Interop.SharpUpNative.SID_AND_ATTRIBUTES)System.Runtime.InteropServices.Marshal.PtrToStructure(
                    new IntPtr(tokenInformation.ToInt64() + i * sidAndAttrSize + IntPtr.Size),
                    typeof(Interop.SharpUpNative.SID_AND_ATTRIBUTES));

                IntPtr pstr = IntPtr.Zero;
                Interop.SharpUpNative.ConvertSidToStringSid(sidAndAttributes.Sid, out pstr);
                userSIDs[i] = System.Runtime.InteropServices.Marshal.PtrToStringAuto(pstr);
                Interop.SharpUpNative.LocalFree(pstr);
            }

            System.Runtime.InteropServices.Marshal.FreeHGlobal(tokenInformation);
            return userSIDs;
        }

        internal static bool IsModifiableRegistryKey(Microsoft.Win32.RegistryKey key)
        {
            RegistryRights[] modifyRights =
            {
                RegistryRights.ChangePermissions,
                RegistryRights.FullControl,
                RegistryRights.TakeOwnership,
                RegistryRights.SetValue,
                RegistryRights.WriteKey
            };

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            AuthorizationRuleCollection rules = key.GetAccessControl()
                .GetAccessRules(true, true, typeof(SecurityIdentifier));

            foreach (RegistryAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference) ||
                    rule.IdentityReference == identity.User)
                {
                    foreach (var accessRight in modifyRights)
                    {
                        if ((accessRight & rule.RegistryRights) == accessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            return false;
        }
    }
}
