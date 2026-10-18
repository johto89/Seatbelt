#nullable disable
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Xml;
using Seatbelt.Output.TextWriters;
using Seatbelt.Output.Formatters;
using Seatbelt.Util;

namespace Seatbelt.Commands.PrivEsc
{
    // Ported from GhostPack/SharpUp - checks for modifiable scheduled task files
    internal class ModifiableScheduledTaskFileCommand : CommandBase
    {
        public override string Command => "SharpUpModifiableScheduledTask";
        public override string Description => "[SharpUp] Checks for scheduled tasks with modifiable target files";
        public override CommandGroup[] Group => new[] { CommandGroup.PrivEsc };
        public override bool SupportRemote => false;
        public override SeverityLevel Severity => SeverityLevel.High;

        public ModifiableScheduledTaskFileCommand(Runtime runtime) : base(runtime) { }

        public override IEnumerable<CommandDTOBase?> Execute(string[] args)
        {
            string tasksDir = Environment.GetEnvironmentVariable("SystemRoot");
            if (string.IsNullOrEmpty(tasksDir))
            {
                WriteError("  [X] Could not determine SystemRoot");
                yield break;
            }

            tasksDir += IntPtr.Size == 8 ? "\\System32\\Tasks" : "\\SysWOW64\\Tasks";

            string[] allfiles;
            try
            {
                allfiles = Directory.GetFiles(tasksDir);
            }
            catch (Exception ex)
            {
                WriteError(string.Format("  [X] Could not enumerate scheduled tasks: {0}", ex.Message));
                yield break;
            }

            foreach (string file in allfiles)
            {
                bool taskPerms = SharpUpUtil.CheckAccess(file, FileSystemRights.Write);

                var results = new List<CommandDTOBase?>();
                try
                {
                    XmlDocument xmlDocument = new XmlDocument();
                    xmlDocument.Load(file);
                    XmlNodeList task = xmlDocument.GetElementsByTagName("URI");
                    XmlNodeList command = xmlDocument.GetElementsByTagName("Command");

                    for (int i = 0; i < command.Count; i++)
                    {
                        string commandpath = command[i].InnerXml;
                        bool binPerms = SharpUpUtil.CheckAccess(commandpath, FileSystemRights.Write);

                        if (binPerms || taskPerms)
                        {
                            string taskName = (task.Count > 0) ? task[0].InnerXml : "(unknown)";
                            results.Add(new ModifiableScheduledTaskDTO
                            {
                                TaskName = taskName,
                                TaskPath = file,
                                CommandPath = commandpath,
                                TaskXmlModifiable = taskPerms,
                                TaskBinaryModifiable = binPerms,
                                IsVulnerable = true
                            });
                        }
                    }
                }
                catch (Exception)
                {
                    // not a valid XML task file - skip
                }

                foreach (var r in results) yield return r;
            }
        }

        internal class ModifiableScheduledTaskDTO : CommandDTOBase
        {
            public string TaskName { get; set; }
            public string TaskPath { get; set; }
            public string CommandPath { get; set; }
            public bool TaskXmlModifiable { get; set; }
            public bool TaskBinaryModifiable { get; set; }
            public bool IsVulnerable { get; set; }
        }

        [CommandOutputType(typeof(ModifiableScheduledTaskDTO))]
        internal class ModifiableScheduledTaskTextFormatter : TextFormatterBase
        {
            public ModifiableScheduledTaskTextFormatter(ITextWriter writer) : base(writer) { }

            public override void FormatResult(CommandBase? command, CommandDTOBase result, bool filterResults)
            {
                var dto = (ModifiableScheduledTaskDTO)result;
                WriteLine("  [!] VULNERABLE - Modifiable Scheduled Task:");
                WriteLine("      Task Name              : {0}", dto.TaskName);
                WriteLine("      Task Path              : {0}", dto.TaskPath);
                WriteLine("      Command                : {0}", dto.CommandPath);
                WriteLine("      Task XML Modifiable    : {0}", dto.TaskXmlModifiable);
                WriteLine("      Task Binary Modifiable : {0}", dto.TaskBinaryModifiable);
            }
        }
    }
}
#nullable enable
