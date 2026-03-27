using System;
using System.Runtime.InteropServices;

class RDPShadowDetector
{
    private static bool verbose = false;
    private static int ord = 0; // counter for PrintObject
    private const uint DIRECTORY_QUERY = 0x0001;
    private const uint DIRECTORY_TRAVERSE = 0x0002;
    private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
    private const int QUERY_BUFFER_MAX_SIZE = 32 * 1024 * 1024; // 32 MB

    // NTSTATUS values
    private const int STATUS_SUCCESS = 0x00000000;
    private const int STATUS_MORE_ENTRIES = 0x00000105;
    private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_DIRECTORY_INFORMATION
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
    private static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    [DllImport("ntdll.dll")]
    private static extern int NtClose(IntPtr Handle);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    private static string UnicodeStringToString(UNICODE_STRING ustr)
    {
        if (ustr.Buffer == IntPtr.Zero || ustr.Length == 0) return "";
        return Marshal.PtrToStringUni(ustr.Buffer, ustr.Length / 2);
    }

    private static void PrintObject(OBJECT_DIRECTORY_INFORMATION info)
    {
        if (verbose)
        {
            Console.WriteLine($"TYPE[{ord}]: {UnicodeStringToString(info.TypeName)}");
            Console.WriteLine($"NAME[{ord}]: {UnicodeStringToString(info.Name)}");
            Console.WriteLine();
        }
        ord++;
    }

    private static bool EnumObjects(string dir, string type, string searchedEventName, out int matchingTypeCount, out int matchingNameCount)
    {
        matchingTypeCount = 0;
        matchingNameCount = 0;

        RtlInitUnicodeString(out UNICODE_STRING dirName, dir);

        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<OBJECT_ATTRIBUTES>(),
            RootDirectory = IntPtr.Zero,
            Attributes = 0,
            ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf<UNICODE_STRING>()),
            SecurityDescriptor = IntPtr.Zero,
            SecurityQualityOfService = IntPtr.Zero
        };
        Marshal.StructureToPtr(dirName, oa.ObjectName, false);

        if (NtOpenDirectoryObject(out IntPtr dirHandle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, ref oa) != STATUS_SUCCESS)
        {
            Marshal.FreeHGlobal(oa.ObjectName);
            return false;
        }

        bool result = true;
        bool firstCall = true;
        uint context = 0;
        int bufferSize = 2048;
        int status = 0;

        while (true)
        {
            IntPtr buffer = IntPtr.Zero;

            do
            {
                bufferSize *= 2;
                if (bufferSize > QUERY_BUFFER_MAX_SIZE)
                {
                    bufferSize = QUERY_BUFFER_MAX_SIZE;
                    break;
                }
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal(bufferSize);
                status = NtQueryDirectoryObject(dirHandle, buffer, (uint)bufferSize, false, firstCall, ref context, out uint bytesReturned);
            }
            while ((status == STATUS_BUFFER_TOO_SMALL || status == STATUS_MORE_ENTRIES) && bufferSize < QUERY_BUFFER_MAX_SIZE);

            if (status != STATUS_SUCCESS && status != STATUS_MORE_ENTRIES && status != STATUS_NO_MORE_ENTRIES)
            {
                result = false;
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                break;
            }

            int structSize = Marshal.SizeOf<OBJECT_DIRECTORY_INFORMATION>();
            int offset = 0;
            while (offset + structSize <= bufferSize)
            {
                OBJECT_DIRECTORY_INFORMATION info = Marshal.PtrToStructure<OBJECT_DIRECTORY_INFORMATION>(IntPtr.Add(buffer, offset));
                if (info.Name.Buffer == IntPtr.Zero) break;

                PrintObject(info);

                string typeName = UnicodeStringToString(info.TypeName);
                string name = UnicodeStringToString(info.Name);
                if (typeName == type)
                {
                    matchingTypeCount++;
                    if (name.Contains(searchedEventName)) matchingNameCount++;
                }

                offset += structSize;
            }

            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);

            if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_SUCCESS) break;
            firstCall = false;
        }

        NtClose(dirHandle);
        Marshal.FreeHGlobal(oa.ObjectName);

        return result;
    }

    static void Main(string[] args)
    {
        uint sid = INVALID_SESSION_ID;
        if (args.Length > 0)
        {
            if (!uint.TryParse(args[0], out sid))
            {
                Console.WriteLine("Incorrect parameter.\nUsage: program <session-number> [v]");
                return;
            }
            if (args.Length > 1 && args[1] == "v") verbose = true;
        }
        else
        {
            ProcessIdToSessionId(GetCurrentProcessId(), out sid);
        }

        Console.WriteLine($"Checking Windows session {sid}...");

        string dir = $"\\Sessions\\{sid}\\BaseNamedObjects";
        string objectType = "Event";

        if (EnumObjects(dir, objectType, "RDPSchedulerEvent", out int typeCount, out int nameCount))
        {
            Console.WriteLine($"Found objects of '{objectType}' type: {typeCount}");
            if (nameCount > 0)
                Console.WriteLine($"*** Session {sid} looks like being shadowed! ***");
            else
                Console.WriteLine($"Shadowing not detected for session {sid}.");
        }
        else
        {
            Console.WriteLine("Failed to enumerate objects.");
        }
    }
}