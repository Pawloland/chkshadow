param(
    [uint32]$SessionId,
    [switch]$Verbose
)

if (-not $SessionId) { $SessionId = (Get-Process -Id $PID).SessionId }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ShadowChecker
{
    private const uint DIRECTORY_QUERY = 0x0001;
    private const uint DIRECTORY_TRAVERSE = 0x0002;
    private const int STATUS_SUCCESS = 0x00000000;
    private const int STATUS_MORE_ENTRIES = 0x00000105;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(
        out IntPtr DirectoryHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes
    );

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(
        IntPtr DirectoryHandle,
        IntPtr Buffer,
        uint Length,
        bool ReturnSingleEntry,
        bool RestartScan,
        ref uint Context,
        out uint ReturnLength
    );

    [DllImport("ntdll.dll")]
    private static extern void RtlInitUnicodeString(
        out UNICODE_STRING DestinationString,
        [MarshalAs(UnmanagedType.LPWStr)] string SourceString
    );

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    private static string UnicodeStringToString(UNICODE_STRING ustr)
    {
        if (ustr.Buffer == IntPtr.Zero || ustr.Length == 0) return "";
        return Marshal.PtrToStringUni(ustr.Buffer, ustr.Length / 2);
    }

    public static bool CheckShadow(uint sessionId, bool verbose)
    {
        string dir = "\\Sessions\\" + sessionId.ToString() + "\\BaseNamedObjects";
        string objectType = "Event";
        string searchedEventName = "RDPSchedulerEvent";

        UNICODE_STRING dirName;
        RtlInitUnicodeString(out dirName, dir);

        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.RootDirectory = IntPtr.Zero;
        oa.Attributes = 0;
        oa.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(dirName, oa.ObjectName, false);
        oa.SecurityDescriptor = IntPtr.Zero;
        oa.SecurityQualityOfService = IntPtr.Zero;

        IntPtr dirHandle;
        if (NtOpenDirectoryObject(out dirHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, ref oa) != STATUS_SUCCESS)
        {
            Marshal.FreeHGlobal(oa.ObjectName);
            return false;
        }

        bool firstCall = true;
        uint context = 0;
        int bufferSize = 2048;
        int typeCount = 0;
        int nameCount = 0;

        while (true)
        {
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            uint bytesReturned;
            int status = NtQueryDirectoryObject(dirHandle, buffer, (uint)bufferSize, false, firstCall, ref context, out bytesReturned);

            if (status == STATUS_BUFFER_TOO_SMALL)
            {
                Marshal.FreeHGlobal(buffer);
                bufferSize *= 2;
                continue;
            }

            if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES && status != STATUS_NO_MORE_ENTRIES)
            {
                Marshal.FreeHGlobal(buffer);
                NtClose(dirHandle);
                Marshal.FreeHGlobal(oa.ObjectName);
                return false;
            }

            int structSize = Marshal.SizeOf(typeof(OBJECT_DIRECTORY_INFORMATION));
            int offset = 0;
            while (offset + structSize <= bufferSize)
            {
                OBJECT_DIRECTORY_INFORMATION info = (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(IntPtr.Add(buffer, offset), typeof(OBJECT_DIRECTORY_INFORMATION));
                if (info.Name.Buffer == IntPtr.Zero) break;

                string typeName = UnicodeStringToString(info.TypeName);
                string name = UnicodeStringToString(info.Name);

                if (verbose)
                {
                    Console.WriteLine("TYPE: " + typeName);
                    Console.WriteLine("NAME: " + name);
                    Console.WriteLine();
                }

                if (typeName == objectType)
                {
                    typeCount++;
                    if (name.Contains(searchedEventName)) nameCount++;
                }

                offset += structSize;
            }

            Marshal.FreeHGlobal(buffer);

            if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_SUCCESS) break;
            firstCall = false;
        }

        NtClose(dirHandle);
        Marshal.FreeHGlobal(oa.ObjectName);

        Console.WriteLine(string.Format("Found objects of '{0}' type: {1}", objectType, typeCount));
        if (nameCount > 0)
            Console.WriteLine(string.Format("*** Session {0} looks like being shadowed! ***", sessionId));
        else
            Console.WriteLine(string.Format("Shadowing not detected for session {0}.", sessionId));

        return true;
    }
}
"@ -Language CSharp


# Call the C# method
[ShadowChecker]::CheckShadow($SessionId, $Verbose.IsPresent)