using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace RazeWatch;
public sealed class ResourceLimits : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] struct Basic { public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinWorking,MaxWorking;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct Io {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
    [StructLayout(LayoutKind.Sequential)] struct Extended {public Basic Basic;public Io Io;public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;}
    [StructLayout(LayoutKind.Sequential)] struct Cpu {public uint Flags,Rate;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateJobObject(IntPtr attributes,string? name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(SafeFileHandle job,int cls,IntPtr data,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(SafeFileHandle job,IntPtr process);
    readonly SafeFileHandle job;
    static ResourceLimits? collectorLimits;
    public ResourceLimits(long memoryBytes,uint cpuPercent,bool killOnClose)
    {
        job=CreateJobObject(IntPtr.Zero,null);if(job.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
        try {Set(9,new Extended{Basic=new Basic{Flags=0x200|(killOnClose?0x2000u:0)},JobMemory=(UIntPtr)memoryBytes});Set(15,new Cpu{Flags=5,Rate=cpuPercent*100});}catch {job.Dispose();throw;}
    }
    void Set<T>(int cls,T value)where T:struct {int n=Marshal.SizeOf<T>();IntPtr p=Marshal.AllocHGlobal(n);try{Marshal.StructureToPtr(value,p,false);if(!SetInformationJobObject(job,cls,p,(uint)n))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{Marshal.FreeHGlobal(p);}}
    public void Assign(Process process){if(!AssignProcessToJobObject(job,process.Handle))throw new Win32Exception(Marshal.GetLastWin32Error());}
    public static void Activate(Evidence e)
    {
        var at=DateTimeOffset.UtcNow;
        try {if(collectorLimits==null){var limits=new ResourceLimits(1024L*1024*1024,25,false);try{limits.Assign(Process.GetCurrentProcess());collectorLimits=limits;}catch{limits.Dispose();throw;}}
            e.Status(new Health("job-limits",at,DateTimeOffset.UtcNow,"active",0,0,"Kernel job: collector + inherited children 1 GiB committed memory, 25% CPU cap relative to containing job. WMI service/kernel costs excluded; children use 256 MiB kill-on-close jobs."));}
        catch(Exception ex){e.Status(new Health("job-limits",at,DateTimeOffset.UtcNow,"degraded",ex.HResult,0,"Native limits unavailable: "+ex.Message));}
    }
    public void Dispose()=>job.Dispose();
}
