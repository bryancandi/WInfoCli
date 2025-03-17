// WInfoCli - Windows Information Command Line Tool
// Copyright (c) 2025 Bryan Candiliere

// Licensed under the MIT License. See LICENSE in the project root for license information.
// https://github.com/bryancandi/WInfoCli/blob/master/LICENSE.txt

using System;
using System.Reflection;
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
            Console.WriteLine("    --help, -h\n\tDisplay this help message.\n");
            Console.WriteLine("    --version, -v\n\tDisplay application version information.\n");
            Console.WriteLine("    --no-special-dirs, -n\n\tDo not display special user directories.\n");
            Console.WriteLine("    --show-paths, -p\n\tDisplay environment PATHs.\n");
            Console.WriteLine("    --logo1\n\tDisplay Windows 11 style ASCII logo.\n");
            Console.WriteLine("    --logo2\n\tDisplay Windows 10 style ASCII logo.\n");
            Console.WriteLine("    --logo3\n\tDisplay classic style Windows ASCII logo.");
            Console.WriteLine();
            return;
        }

        if (args.Contains("--version") || args.Contains("-v"))
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            Console.WriteLine($"WInfoCli - Windows Information Command Line Tool\nVersion: {version?.ToString() ?? "unknown version"}");
            return;
        }

        bool showSpecialDirs = !args.Contains("--no-special-dirs") && !args.Contains("-n");

        bool showPaths = args.Contains("--show-paths") || args.Contains("-p");

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
        DisplayUserInfo(showSpecialDirs);
        DisplayEnvironmentPaths(showPaths);
        Exit();
    }

    public static void DisplayComputerInfo()
    {
        Console.WriteLine("Computer Information");
        Console.WriteLine(LineBreak);
        Console.WriteLine($"Host:\t\t\t{GetComputerModel()}");
        Console.WriteLine($"Processor:\t\t{GetCPUName()}");
        Console.WriteLine($"Graphics:\t\t{GetGPUName()}");
        string processorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? string.Empty;
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
        string osBits = (Environment.Is64BitOperatingSystem) ? "64-bit" : "32-bit";
        Console.WriteLine($"OS:\t\t\t{GetFriendlyOsName()} ({osBits}) Build {Environment.OSVersion.Version.Build}");
        Console.WriteLine($"OS Platform:\t\t{Environment.OSVersion.Platform}");
        Console.WriteLine($"OS Version String:\t{Environment.OSVersion.VersionString}");
        if (!string.IsNullOrEmpty(Environment.OSVersion.ServicePack))
        {
            Console.WriteLine($"Service Pack:\t\t{Environment.OSVersion.ServicePack}");
        }
        Console.WriteLine($"Windows Shell:\t\t{GetWindowsShell()}");
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

    public static void DisplayUserInfo(bool showSpecialDirs)
    {
        Console.WriteLine("User Information");
        Console.WriteLine(LineBreak);
        Console.WriteLine($"User Name:\t\t{Environment.UserName}");
        Console.WriteLine($"User Domain Name:\t{Environment.UserDomainName}");
        Console.WriteLine($"Machine Name:\t\t{Environment.MachineName}");
        Console.WriteLine(GetUserDirs(showSpecialDirs));
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplayEnvironmentPaths(bool showPaths)
    {
        if (showPaths)
        {
            Console.WriteLine("Environment PATHs");
            Console.WriteLine(LineBreak);
            // Get user path
            string userPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? string.Empty;
            Console.WriteLine("User PATH:");
            string[] userPaths = userPath.Split(';');
            foreach (string path in userPaths)
            {
                Console.WriteLine($"    {path}");
            }
            // Get system path
            string systemPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? string.Empty;
            Console.WriteLine("System PATH:");
            string[] systemPaths = systemPath.Split(';');
            foreach (string path in systemPaths)
            {
                Console.WriteLine($"    {path}");
            }
            Console.WriteLine(LineBreak);
            Console.WriteLine();
        }
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
            return "Unknown";
        }
        catch (Exception ex)
        {
            return $"Error retrieving model information: {ex.Message}";
        }
    }

    static string GetCPUName()
    {
        string cpuName = string.Empty;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
            {
                foreach (var obj in searcher.Get())
                {
                    cpuName = obj["Name"].ToString();
                }
            }
        }
        catch (Exception)
        {
            return "Unknown";
        }
        return cpuName;
    }

    static string GetGPUName()
    {
        string gpuName = string.Empty;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController"))
            {
                foreach (var obj in searcher.Get())
                {
                    // List each GPU on a new line
                    gpuName += $"{obj["Name"].ToString()}\n\t\t\t";
                }
            }
        }
        catch (Exception)
        {
            return "Unknown";
        }
        return gpuName.Trim();
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

    public static string GetWindowsShell()
    {
        try
        {
            int currentProcessId = Process.GetCurrentProcess().Id;
            ManagementObjectSearcher query = new ManagementObjectSearcher($"SELECT * FROM Win32_Process WHERE ProcessId = {currentProcessId}");
            foreach (ManagementObject process in query.Get())
            {
                int parentProcessId = Convert.ToInt32(process["ParentProcessId"]);
                Process parentProcess = Process.GetProcessById(parentProcessId);
                return parentProcess.ProcessName;
            }
        }
        catch (Exception)
        {
            return "Unknown";
        }
        return "Unknown";
    }

    public static string GetDiskInformation()
    {
        string result = String.Empty;
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3");
            foreach (ManagementObject drive in searcher.Get())
            {
                try
                {
                    string driveLetter = drive["DeviceID"]?.ToString();
                    string fileSystem = drive["FileSystem"]?.ToString();
                    ulong totalSpace = (ulong)drive["Size"] / GibibyteUL;
                    ulong freeSpace = (ulong)drive["FreeSpace"] / GibibyteUL;
                    // List each drive on a new line
                    result += $"{driveLetter}\\ {totalSpace} GiB ({freeSpace} GiB free) - {fileSystem}\n\t\t\t";
                }
                catch (Exception)
                {
                    // Skip this drive if there is an error
                    result += "";
                }
            }
        }
        catch (Exception ex)
        {
            result += $"Error retrieving drive information: {ex.Message}";
        }
        return result.Trim();
    }

    public static string GetUserDirs(bool showSpecialDirs)
    {
        string dirs = string.Empty;
        try
        {
            dirs += $"User Profile:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\n";
            if (showSpecialDirs)
            {
                dirs += $"Desktop:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)}\n";
                dirs += $"Documents:\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)}\n";
                dirs += $"Music:\t\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyMusic)}\n";
                dirs += $"Pictures\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)}\n";
                dirs += $"Videos:\t\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyVideos)}\n";
            }
            dirs += $"Application Data:\t{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}";
        }
        catch (Exception)
        {
            return "";
        }
        return dirs.Trim();
    }

    // Helper Method(s)
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

    // ASCII Logos
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
        Console.ReadKey(true);
    }
}
