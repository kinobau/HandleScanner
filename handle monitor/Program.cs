using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Management;
using System.IO;

class HandleScanner
{
    const int SystemExtendedHandleInformation = 0x40;
    const uint PROCESS_DUP_HANDLE = 0x0040;
    const uint DUPLICATE_SAME_ACCESS = 0x2;
    const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    enum ObjectInformationClass { ObjectTypeInformation = 2 }

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length, MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleCount;
        public uint Reserved;
    }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    [DllImport("ntdll.dll")]
    static extern int NtQueryObject(IntPtr Handle, ObjectInformationClass ObjectInformationClass, IntPtr ObjectInformation, uint ObjectInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    static extern uint GetProcessId(IntPtr handle);

    static string GetAccessRightsDetails(uint access)
    {
        var flags = new[]
        {
            (0x0002, "VM_READ"),
            (0x0010, "VM_OPERATION"),
            (0x0020, "VM_WRITE"),
            (0x0008, "CREATE_THREAD"),
            (0x00100000, "QUERY_INFORMATION"),
            (0x00040000, "READ_CONTROL"),
            (0x00020000, "WRITE_DAC"),
            (0x00010000, "DELETE"),
            (0x000F0000, "ALL_ACCESS")
        };

        var sb = new StringBuilder();
        foreach (var (mask, name) in flags)
        {
            if ((access & mask) == mask)
                sb.Append(name + ", ");
        }
        return sb.Length > 2 ? sb.ToString(0, sb.Length - 2) : "UNKNOWN";
    }

    static bool IsSigned(string path)
    {
        try
        {
            X509Certificate cert = X509Certificate.CreateFromSignedFile(path);
            return cert != null;
        }
        catch
        {
            return false;
        }
    }

    static void Main()
    {
        Console.WriteLine("[*] Scanning for handles...\n");

        var target = Process.GetProcessesByName("notepad");
        if (target.Length == 0)
        {
            Console.WriteLine("[-] Specified process not running.");
            return;
        }

        int targetPid = target[0].Id;
        Console.WriteLine($"[+] Target PID: {targetPid}");

        IntPtr buffer = IntPtr.Zero;
        uint length = 0x100000, needed;
        int status;

        do
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            buffer = Marshal.AllocHGlobal((int)length);
            status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out needed);
            if (status == STATUS_INFO_LENGTH_MISMATCH) length = needed;
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (status != 0)
        {
            Console.WriteLine($"[-] NtQuerySystemInformation failed: 0x{status:X}");
            return;
        }

        long count = Marshal.ReadInt64(buffer);
        IntPtr ptr = buffer + IntPtr.Size * 2;
        int size = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();

        for (long i = 0; i < count; i++, ptr += size)
        {
            var handle = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(ptr);
            int ownerPid = handle.UniqueProcessId.ToInt32();
            if (ownerPid == targetPid || ownerPid == Process.GetCurrentProcess().Id) continue;

            IntPtr ownerProc = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
            if (ownerProc == IntPtr.Zero) continue;

            if (DuplicateHandle(ownerProc, handle.HandleValue, Process.GetCurrentProcess().Handle, out IntPtr dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
            {
                IntPtr objInfo = Marshal.AllocHGlobal(0x1000);
                status = NtQueryObject(dupHandle, ObjectInformationClass.ObjectTypeInformation, objInfo, 0x1000, out _);
                if (status >= 0)
                {
                    var typeInfo = Marshal.PtrToStructure<OBJECT_TYPE_INFORMATION>(objInfo);
                    string typeName = Marshal.PtrToStringUni(typeInfo.Name.Buffer, typeInfo.Name.Length / 2);
                    if (typeName == "Process")
                    {
                        uint resolvedPid = GetProcessId(dupHandle);
                        if (resolvedPid == targetPid)
                        {
                            try
                            {
                                var proc = Process.GetProcessById(ownerPid);
                                string exePath = proc.MainModule.FileName;
                                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                                uint granted = handle.GrantedAccess;

                                // Check if the process is signed
                                bool isSigned = IsSigned(exePath);

                                // Only alert if process has full rights and is not signed
                                if (!isSigned && (granted & 0x1FFFFF) == 0x1FFFFF)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine($"\n[!] UNSIGNED PROCESS WITH FULL ACCESS ({timestamp}):");
                                    Console.ResetColor();
                                    Console.WriteLine($"    - Cheating PID: {ownerPid}");
                                    Console.WriteLine($"    - Process Name: {proc.ProcessName}");
                                    Console.WriteLine($"    - Executable: {exePath}");
                                    Console.WriteLine($"    - Handle Value: {handle.HandleValue}");
                                    Console.WriteLine($"    - Access Rights: 0x{granted:X} (VM_READ, VM_OPERATION, VM_WRITE, CREATE_THREAD, QUERY_INFORMATION, READ_CONTROL, WRITE_DAC, DELETE, ALL_ACCESS)");
                                }
                            }

                            catch { }

                        }
                    }
                }
                Marshal.FreeHGlobal(objInfo);
                CloseHandle(dupHandle);
            }
            CloseHandle(ownerProc);
        }

        Marshal.FreeHGlobal(buffer);
        Console.WriteLine("\n[*] Scan complete.");
        Console.ReadKey();
    }
}