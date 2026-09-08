using System.ComponentModel;
using System.Runtime.InteropServices;
namespace RazeWatch;
public static class AuditPolicy
{
    public const string FilteringConnectionGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}";
    public static uint FilteringConnectionFlags()
    {
        IntPtr guid = Marshal.AllocHGlobal(16), policies = IntPtr.Zero;
        try {
            Marshal.StructureToPtr(new Guid(FilteringConnectionGuid), guid, false);
            if (!AuditQuerySystemPolicy(guid, 1, out policies)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.PtrToStructure<Policy>(policies).Flags;
        } finally { Marshal.FreeHGlobal(guid); if (policies != IntPtr.Zero) AuditFree(policies); }
    }
    [StructLayout(LayoutKind.Sequential)] struct Policy {public Guid Subcategory;public uint Flags;public Guid Category;}
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditEnumerateSubCategories(IntPtr category,[MarshalAs(UnmanagedType.U1)]bool all,out IntPtr guids,out uint count);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(IntPtr guids,uint count,out IntPtr policies);
    [DllImport("advapi32.dll",EntryPoint="AuditLookupSubCategoryNameW",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditLookupSubCategoryName(ref Guid guid,out IntPtr name);
    [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
    public static void Collect(Evidence e)
    {
        var at=DateTimeOffset.UtcNow;IntPtr guids=IntPtr.Zero,policies=IntPtr.Zero;int records=0;
        try {
            if(!AuditEnumerateSubCategories(IntPtr.Zero,true,out guids,out uint count))throw new Win32Exception(Marshal.GetLastWin32Error());
            if(!AuditQuerySystemPolicy(guids,count,out policies))throw new Win32Exception(Marshal.GetLastWin32Error());
            for(int i=0;i<count;i++) {
                var p=Marshal.PtrToStructure<Policy>(policies+i*Marshal.SizeOf<Policy>());string? name=null;
                if(AuditLookupSubCategoryName(ref p.Subcategory,out var ptr)){try{name=Marshal.PtrToStringUni(ptr);}finally{AuditFree(ptr);}}
                e.Write("audit-policy.jsonl",new {Utc=DateTimeOffset.UtcNow,Subcategory=p.Subcategory,Category=p.Category,Name=name,RawFlags=p.Flags,SuccessEnabled=(p.Flags&1)!=0,FailureEnabled=(p.Flags&2)!=0,Status=(p.Flags&3)==0?"auditing-disabled":"enabled",Coverage="Current system policy only; per-user overrides and historical policy may differ."});records++;
            }
            e.Status(new Health("audit-policy-native",at,DateTimeOffset.UtcNow,"success",0,records,"Read-only AuditQuerySystemPolicy; GUID and raw flags, independent of OS language. No policy modified."));
        }catch(Win32Exception ex){e.Status(new Health("audit-policy-native",at,DateTimeOffset.UtcNow,ex.NativeErrorCode==5?"access-denied":"error",ex.NativeErrorCode,records,ex.Message));}
        finally{if(guids!=IntPtr.Zero)AuditFree(guids);if(policies!=IntPtr.Zero)AuditFree(policies);}
    }
}
