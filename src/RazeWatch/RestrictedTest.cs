using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
namespace RazeWatch;
public static class RestrictedTest
{
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,int access,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateRestrictedToken(SafeAccessTokenHandle token,int flags,int count,IntPtr sids,int privs,IntPtr privileges,int restrictCount,IntPtr restricted,out SafeAccessTokenHandle newToken);
    public static bool Run()
    {
        if(!OpenProcessToken(Process.GetCurrentProcess().Handle,0xB,out var token))throw new Win32Exception(Marshal.GetLastWin32Error());
        using(token) {
            if(!CreateRestrictedToken(token,5,0,IntPtr.Zero,0,IntPtr.Zero,0,IntPtr.Zero,out var restricted))throw new Win32Exception(Marshal.GetLastWin32Error());
            using(restricted)return WindowsIdentity.RunImpersonated(restricted,()=>{
                bool admin=new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
                bool denied=false;
                try {using var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName));using var record=reader.ReadEvent(TimeSpan.FromSeconds(2));}
                catch(UnauthorizedAccessException){denied=true;}
                catch(EventLogException ex)when((ex.HResult&0xffff)==5){denied=true;}
                bool network=Network.Snapshot(2,true).Count>=0;
                Console.WriteLine($"Restricted native access: admin={admin}; SecurityDenied={denied}; endpointApi={network}");
                return !admin && denied && network;
            });
        }
    }
}
