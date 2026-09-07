using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace RazeWatch;

public static class Network
{
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int cls, uint reserved);
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int cls, uint reserved);
    public static List<Flow> Snapshot(int family, bool tcp)
    {
        var start = DateTimeOffset.UtcNow; int size = 0;
        uint Call(IntPtr p) => tcp ? GetExtendedTcpTable(p, ref size, false, family, 5, 0) : GetExtendedUdpTable(p, ref size, false, family, 1, 0);
        uint rc = Call(IntPtr.Zero);
        if (rc != 122 && rc != 0) throw new Win32Exception((int)rc);
        for (int retry = 0; retry < 4; retry++)
        {
            if (size > 16 * 1024 * 1024) throw new IOException("Endpoint table limit");
            int allocated = size; var ptr = Marshal.AllocHGlobal(Math.Max(size, 4));
            try
            {
                rc = Call(ptr); if (rc == 122) continue;
                if (rc != 0) throw new Win32Exception((int)rc);
                int count = Marshal.ReadInt32(ptr); int row = family == 2 ? tcp ? 24 : 12 : tcp ? 56 : 28;
                if (count < 0 || 4L + count * (long)row > allocated) throw new IOException("Invalid endpoint table size");
                var list = new List<Flow>(count); var end = DateTimeOffset.UtcNow;
                for (int i = 0; i < count; i++)
                {
                    byte[] b = new byte[row]; Marshal.Copy(ptr + 4 + i * row, b, 0, row);
                    int U(int o) => BitConverter.ToInt32(b, o);
                    int Port(int o) => b[o] * 256 + b[o + 1];
                    string Ip(int o, bool v6) => v6 ? new IPAddress(b.AsSpan(o, 16), (uint)U(o + 16)).ToString() : new IPAddress(b.AsSpan(o, 4)).ToString();
                    list.Add(family == 2
                        ? new Flow(start, end, tcp ? "TCP" : "UDP", 4, U(tcp ? 20 : 8), Ip(tcp ? 4 : 0, false), Port(tcp ? 8 : 4), tcp ? Ip(12, false) : null, tcp ? Port(16) : null, tcp ? U(0).ToString() : "bound", "IPHelper-poll")
                        : new Flow(start, end, tcp ? "TCP" : "UDP", 6, U(tcp ? 52 : 24), Ip(0, true), Port(20), tcp ? Ip(24, true) : null, tcp ? Port(44) : null, tcp ? U(48).ToString() : "bound", "IPHelper-poll"));
                }
                return list;
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }
        throw new IOException("Endpoint table changed during four reads");
    }
}
