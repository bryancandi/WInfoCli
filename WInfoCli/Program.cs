// WInfoCli
// Copyright (c) 2025 Bryan Candiliere

// Licensed under the MIT License. See LICENSE in the project root for license information.
// https://github.com/bryancandi/WInfoCli/blob/master/LICENSE.txt

using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Management;
using System.Diagnostics;
using Microsoft.Win32;

public class WInfoCli
{

    private const string LineBreak = "--------------------------------------------------------------------------------";
    private const double Gibibyte = 1024.0 * 1024.0 * 1024.0;
    private const ulong GibibyteUL = 1024 * 1024 * 1024;

    public static void Main(string[] args)
    {
        if (args.Contains("--help") || args.Contains("-h") || args.Contains("/h") || args.Contains("/H") || args.Contains("/?"))
        {
            Console.WriteLine($"WInfoCli - Windows Information Command Line Tool");
            Console.WriteLine("Copyright (c) 2025 Bryan Candiliere");
            Console.WriteLine();
            Console.WriteLine("Usage: WInfoCli.exe [Options]");          
            Console.WriteLine("Options:");
            Console.WriteLine("  --help, -h\t\tShow this help message");
            Console.WriteLine("  --version, -v\t\tShow version information");
            Console.WriteLine("  --logo1\t\tDisplay Windows 11 style ASCII logo");
            Console.WriteLine("  --logo2\t\tDisplay Windows 10 style ASCII logo");
            Console.WriteLine("  --logo3\t\tDisplay classic style Windows ASCII logo");
            Console.WriteLine();
            return;
        }

        if (args.Contains("--version") || args.Contains("-v"))
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            Console.WriteLine($"WInfoCli {version}");
            Console.WriteLine();
            return;
        }

        if (args.Contains("--logo1"))
        {
            DisplayAsciiLogo11();
        }
        else if (args.Contains("--logo2"))
        {
            DisplayAsciiLogo10();
        }
        else if (args.Contains("--logo3"))
        {
            DisplayAsciiLogoColor();
        }
        else
        {
            Console.ResetColor();
            Console.WriteLine();
        }

        DisplayComputerInfo();
        DisplaySystemInfo();
        DisplayUserInfo();
        Exit();
    }

    public static void DisplayComputerInfo()
    {
        Console.WriteLine("Computer Information");
        Console.WriteLine(LineBreak);
        Console.WriteLine($"Host:\t\t\t{GetComputerModel()}");
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
        double totalPhysicalMemory = (double)GetTotalPhysicalMemory() / Gibibyte;
        Console.WriteLine($"Total Physical Memory:\t{totalPhysicalMemory:F2} GiB");
        double freePhysicalMemory = (double)GetFreePhysicalMemory() / Gibibyte;
        Console.WriteLine($"Free Physical Memory:\t{freePhysicalMemory:F2} GiB");
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
            Console.WriteLine($"Service Pack:\t\t{Environment.OSVersion.ServicePack}");
        }
        Console.WriteLine($"Windows Directory:\t{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}");
        Console.WriteLine($"System Directory:\t{Environment.SystemDirectory}");
        Console.WriteLine($"Logical Drives:\t\t{GetDiskInformation()}");
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
        Console.WriteLine($"User Profile:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}");
        Console.WriteLine($"Application Data:\t{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}");        
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static string GetRegistryString(string path, string key)
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
        catch (Exception)
        {
            return "";
        }
        return "";
    }

    public static string GetComputerModel()
    {
        try
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
            {
                foreach (ManagementObject wmi in searcher.Get())
                {
                    string manufacturer = wmi["Manufacturer"]?.ToString().Trim();
                    string model = wmi["Model"]?.ToString().Trim();
                    if (!string.IsNullOrEmpty(manufacturer) && !string.IsNullOrEmpty(model))
                    {
                        return $"{manufacturer} {model}";
                    }
                    else if (!string.IsNullOrEmpty(manufacturer))
                    {
                        return manufacturer;
                    }
                    else if (!string.IsNullOrEmpty(model))
                    {
                        return model;
                    }
                }
            }
            return "Unknown machine type";
        }
        catch (Exception ex)
        {
            return $"Error querying WMI: {ex.Message}";
        }
    }

    public static string GetFriendlyOsName()
    {
        string ProductName = GetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
        if (!string.IsNullOrEmpty(ProductName))
        {
            string displayName = (ProductName.StartsWith("Microsoft") ? "" : "Microsoft ") + ProductName;
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
                return (ulong.Parse(obj["FreePhysicalMemory"]?.ToString()) * 1024);
            }
        }
        return 0;
    }

    public static string GetDiskInformation()
    {
        string result = "";
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3");
            foreach (ManagementObject drive in searcher.Get())
            {
                try
                {
                    string driveLetter = drive["DeviceID"]?.ToString();
                    ulong totalSpace = (ulong)drive["Size"] / GibibyteUL;
                    ulong freeSpace = (ulong)drive["FreeSpace"] / GibibyteUL;
                    result += $"{driveLetter}\\ {totalSpace} GiB ({freeSpace} GiB free)\n\t\t\t";
                }
                catch (Exception ex)
                {
                    result += $"Error retrieving information for one drive: {ex.Message}";
                }
            }
        }
        catch (Exception ex)
        {
            result = $"Error querying WMI: {ex.Message}";
        }
        return result.Trim();
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
        foreach (string line in asciiLogo.Split('\n'))
        {
            Console.WriteLine(line);
            Thread.Sleep(150);
        }
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
        foreach (string line in asciiLogo.Split('\n'))
        {
            Console.WriteLine(line);
            Thread.Sleep(150);
        }
        Console.ResetColor();
    }

    public static void DisplayAsciiLogoColor()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"
//////////  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write(@"
//////////  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(@"//////////");
        Thread.Sleep(150);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write(@"//////////  ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(@"//////////
");
        Thread.Sleep(150);
        Console.ResetColor();
    }

    public static void Exit()
    {
        Console.WriteLine("Press any key to exit.");
        Console.ReadLine();
    }
}
