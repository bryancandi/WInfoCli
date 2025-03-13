using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Management;
using System.Diagnostics;
using Microsoft.Win32;

public class WInfoCli
{

    private const string LineBreak = "--------------------------------------------------------------------------------";
    private const double Megabyte = 1024.0 * 1024.0;
    private const double Gigabyte = 1024.0 * 1024.0 * 1024.0;

    public static void Main(string[] args)
    {
        DisplayComputerInfo();
        DisplaySystemInfo();
        DisplayUserInfo();
        Exit();
    }

    public static void DisplayComputerInfo()
    {
        Console.WriteLine("Computer Information");
        Console.WriteLine(LineBreak);
        string cpuName = GetCPUName();
        Console.WriteLine($"Processor:\t\t{cpuName}");
        string processorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
        if (!string.IsNullOrEmpty(processorArchitecture))
        {
            Console.WriteLine($"Processor Architecture:\t{processorArchitecture}");
        }
        else
        {
            Console.WriteLine("Processor Architecture:\tUnknown");
        }
        Console.WriteLine($"Logical Processors:\t{Environment.ProcessorCount}");
        double totalPhysicalMemory = (double)GetTotalPhysicalMemory() / Gigabyte;
        Console.WriteLine($"Total Physical Memory:\t{totalPhysicalMemory:F2} GB");
        double freePhysicalMemory = (double)GetFreePhysicalMemory() / Gigabyte;
        Console.WriteLine($"Free Physical Memory:\t{freePhysicalMemory:F2} GB");
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplaySystemInfo()
    {
        Console.WriteLine("System Information");
        Console.WriteLine(LineBreak);
        string osName = GetFriendlyOsName();
        string osBits = (Environment.Is64BitOperatingSystem) ? "64-bit" : "32-bit";
        Console.WriteLine($"OS:\t\t\t{osName} ({osBits}) Build {Environment.OSVersion.Version.Build}");
        Console.WriteLine($"OS Platform:\t\t{Environment.OSVersion.Platform}");
        Console.WriteLine($"OS Version String:\t{Environment.OSVersion.VersionString}");
        if (!string.IsNullOrEmpty(Environment.OSVersion.ServicePack))
        {
            Console.WriteLine($"Service Pack:\t{Environment.OSVersion.ServicePack}");
        }
        Console.WriteLine($"Windows Directory:\t{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}");
        Console.WriteLine($"System Directory:\t{Environment.SystemDirectory}");
        string[] drives = Environment.GetLogicalDrives();
        Console.WriteLine("Logical Drives:\t\t{0}", String.Join(", ", drives));
        int tickCount = Environment.TickCount;
        TimeSpan uptime = TimeSpan.FromMilliseconds(tickCount);
        string formattedUptime = string.Format("{0} days, {1} hours, {2} minutes, {3} seconds", uptime.Days, uptime.Hours, uptime.Minutes, uptime.Seconds);
        Console.WriteLine($"System Uptime:\t\t{formattedUptime}");
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplayUserInfo()
    {
        Console.WriteLine("User Information");
        Console.WriteLine(LineBreak);
        Console.WriteLine($"User Name:\t\t{Environment.UserName}");
        Console.WriteLine($"User Domain Name:\t{Environment.UserDomainName}");
        Console.WriteLine($"Machine Name:\t\t{Environment.MachineName}");
        Console.WriteLine($"Application Data:\t{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}");
        Console.WriteLine($"Desktop:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)}");
        Console.WriteLine($"My Documents:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)}");
        Console.WriteLine($"My Music:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyMusic)}");
        Console.WriteLine($"My Pictures:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)}");
        Console.WriteLine($"My Videos:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyVideos)}");
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static string HKLM_GetString(string path, string key)
    {
        try
        {
            using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(path))
            {
                if (registryKey != null)
                {
                    object value = registryKey.GetValue(key);
                    if (value is string stringValue)
                    {
                        return stringValue;
                    }
                }
            }
        }
        catch (System.Security.SecurityException)
        {
            Console.WriteLine("Security Exception: Insufficient permissions to access registry.");
        }
        catch (System.IO.IOException)
        {
            Console.WriteLine("IO Exception: Error reading registry.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
        }
        return "";
    }

    public static string GetFriendlyOsName()
    {
        string ProductName = HKLM_GetString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
        int osBuildNumer = Environment.OSVersion.Version.Build;
        if (!string.IsNullOrEmpty(ProductName))
        {
            string displayName = (ProductName.StartsWith("Microsoft") ? "" : "Microsoft ") + ProductName;
            //if (osBuildNumer >= 22000 && ProductName.Contains("Windows 10"))
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) // Windows 11 check
            {
                displayName = displayName.Replace("Windows 10", "Windows 11");
            }
            return displayName;
        }
        return "Microsoft Windows";
    }

    static string GetCPUName()
    {
        string cpuName = string.Empty;
        using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
        {
            foreach (var obj in searcher.Get())
            {
                cpuName = obj["Name"].ToString();
            }
        }
        return cpuName;
    }

    public static ulong GetTotalPhysicalMemory()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
        {
            foreach (ManagementObject obj in searcher.Get())
            {
                return (ulong)obj["TotalPhysicalMemory"];
            }
        }
        return 0;
    }

    public static ulong GetFreePhysicalMemory()
    {
        using (var searcher = new ManagementObjectSearcher("SELECT FreePhysicalMemory FROM Win32_OperatingSystem"))
        {
            foreach (ManagementObject obj in searcher.Get())
            {
                // Convert from kilobytes to bytes
                return (ulong.Parse(obj["FreePhysicalMemory"].ToString()) * 1024);
            }
        }
        return 0;
    }

    public static void DisplayAsciiLogo11()
    {
        Console.ForegroundColor = ConsoleColor.Blue;
        string asciiLogo = @"
//////////  //////////
//////////  //////////
//////////  //////////
//////////  //////////

//////////  //////////
//////////  //////////
//////////  //////////
//////////  //////////
";
        Console.WriteLine(asciiLogo);
        Console.ResetColor();
    }

    public static void DisplayAsciiLogo10()
    {
        Console.ForegroundColor = ConsoleColor.Blue;
        string asciiLogo = @"
    //////////  //////////
   //////////  //////////
  //////////  //////////
 //////////  //////////

    //////////  //////////
   //////////  //////////
  //////////  //////////
 //////////  //////////
";
        Console.WriteLine(asciiLogo);
        Console.ResetColor();
    }

    public static void DisplayAsciiLogoColor()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(@"
//////////  ");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"//////////");

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write(@"//////////  ");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"//////////
");

        Console.ResetColor();
    }

    public static void Exit()
    {
        Console.WriteLine("Press any key to exit.");
        Console.ReadLine();
        DisplayAsciiLogoColor();
    }
}