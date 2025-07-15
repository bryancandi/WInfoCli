// WInfoCli - Windows Information Command Line Tool
// Copyright (c) 2025 Bryan Candiliere

// Licensed under the MIT License. See LICENSE in the project root for license information.
// https://github.com/bryancandi/WInfoCli/blob/master/LICENSE.txt

using System;
using System.Reflection;
using System.Management;
using System.Diagnostics;
using System.Net;
using Microsoft.Win32;

public class WInfoCli
{
    private const string LineBreak = "--------------------------------------------------------------------------------";
    private const double Gibibyte = 1024.0 * 1024.0 * 1024.0;
    private const ulong GibibyteUL = 1024 * 1024 * 1024;

    public static void Main(string[] args)
    {
        // List of valid arguments
        var validArgs = new HashSet<string>
        {
            "--help", "-h", "/h", "/H", "/?",
            "--version", "-v",
            "--ipv6", "-6",
            "--show-dirs", "-d",
            "--show-paths", "-p",
            "--logo", "-l",
            "--logo-win10", "-10",
            "--logo-win11", "-11"
        };

        // Check for invalid arguments
        foreach (var arg in args)
        {
            if (!validArgs.Contains(arg))
            {
                Console.WriteLine($"Invalid command line argument: {arg}");
                Console.WriteLine("For supported arguments, run: 'WInfoCli.exe --help'.");
                return;
            }
        }

        if (args.Contains("--help") || args.Contains("-h") || args.Contains("/h") || args.Contains("/H") || args.Contains("/?"))
        {
            int startYear = 2025;
            int currentYear = DateTime.Now.Year;
            string copyrightYear = "";
            if (currentYear <= startYear)
            {
                copyrightYear = startYear.ToString();
            }
            else
            {
                copyrightYear = $"{startYear}-{currentYear}";
            }

            Console.WriteLine($"WInfoCli - Windows Information Command Line Tool");
            Console.WriteLine($"Copyright (c) {copyrightYear} Bryan Candiliere");
            Console.WriteLine();
            Console.WriteLine("Usage: WInfoCli.exe [Options]");
            Console.WriteLine();
            Console.WriteLine("General Options:");
            Console.WriteLine("    --help, -h\n\tDisplay this help message.");
            Console.WriteLine("    --version, -v\n\tDisplay application version information.\n");
            Console.WriteLine("Display Options:");
            Console.WriteLine("    --ipv6, -6\n\tDisplay IPv6 addresses.");
            Console.WriteLine("    --show-dirs, -d\n\tDisplay special user directories (e.g., Documents, Desktop).");
            Console.WriteLine("    --show-paths, -p\n\tDisplay environment PATH variables for the current system.\n");
            Console.WriteLine("Logo Options:");
            Console.WriteLine("    --logo, -l\n\tDisplay classic style Windows ASCII logo.");
            Console.WriteLine("    --logo-win10, -10\n\tDisplay Windows 10 style ASCII logo.");
            Console.WriteLine("    --logo-win11, -11\n\tDisplay Windows 11 style ASCII logo.");
            Console.WriteLine();
            return;
        }

        if (args.Contains("--version") || args.Contains("-v"))
        {
            Version? version = Assembly.GetExecutingAssembly().GetName().Version;
            Console.WriteLine($"WInfoCli - Windows Information Command Line Tool\nVersion: {version?.ToString() ?? "unknown version"}");
            return;
        }

        bool showIPv6 = args.Contains("--ipv6") || args.Contains("-6");

        bool showSpecialDirs = args.Contains("--show-dirs") || args.Contains("-d");

        bool showPaths = args.Contains("--show-paths") || args.Contains("-p");

        if (args.Contains("--logo") || args.Contains("-l"))
        {
            DisplayAsciiLogoColor();
        }
        else if (args.Contains("--logo-win10") || args.Contains("-10"))
        {
            DisplayAsciiLogo10();
        }
        else if (args.Contains("--logo-win11") || args.Contains("-11"))
        {
            DisplayAsciiLogo11();
        }
        else
        {
            Console.ResetColor();
            Console.WriteLine();
        }

        DisplayComputerInfo();
        DisplaySystemInfo(showIPv6);
        DisplayUserInfo(showSpecialDirs);
        DisplayEnvironmentPaths(showPaths);
        Exit();
    }

    public static void DisplayComputerInfo()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("Computer Information");
        Console.ResetColor();
        Console.WriteLine(LineBreak);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Host");
        Console.ResetColor();
        Console.WriteLine($":\t\t\t{GetComputerModel()}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Processor");
        Console.ResetColor();
        Console.WriteLine($":\t\t{GetCPUName()}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Graphics");
        Console.ResetColor();
        Console.WriteLine($":\t\t{GetGPUName()}");
        string processorArchitecture = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? string.Empty;
        if (!string.IsNullOrEmpty(processorArchitecture))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Processor Architecture");
            Console.ResetColor();
            Console.WriteLine($":\t{processorArchitecture}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Processor Architecture");
            Console.ResetColor();
            Console.WriteLine(":\tUnknown");
        }
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Logical Processors");
        Console.ResetColor();
        Console.WriteLine($":\t{Environment.ProcessorCount}");
        double totalPhysicalMemory = (double)GetTotalPhysicalMemory() / Gibibyte;
        double freePhysicalMemory = (double)GetFreePhysicalMemory() / Gibibyte;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Physical Memory");
        Console.ResetColor();
        Console.WriteLine($":\t{totalPhysicalMemory:F2} GiB ({freePhysicalMemory:F2} GiB free)");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("BIOS Version/Date");
        Console.ResetColor();
        Console.WriteLine($":\t{GetBIOSInformation()}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Embedded Controller");
        Console.ResetColor();
        Console.WriteLine($":\t{GetEmbeddedControllerVersion()}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("UEFI Secure Boot");
        Console.ResetColor();
        Console.WriteLine($":\t{GetUEFISecureBoot()}");
        if (IsBatteryPresent())
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Battery Status");
            Console.ResetColor();
            Console.WriteLine($":\t\t{GetBatteryStatus()}");
        }
        else
        {
            // Do not display battery status if no battery is present
        }
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplaySystemInfo(bool showIPv6)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("System Information");
        Console.ResetColor();
        Console.WriteLine(LineBreak);
        string osBits = (Environment.Is64BitOperatingSystem) ? "64-bit" : "32-bit";
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("OS");
        Console.ResetColor();
        Console.WriteLine($":\t\t\t{GetFriendlyOsName()} ({osBits})");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Version");
        Console.ResetColor();
        Console.WriteLine($":\t\t{GetWindowsReleaseVersion()} (Build {Environment.OSVersion.Version.Build}{GetUpdateBuildRevision()})");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Platform");
        Console.ResetColor();
        Console.WriteLine($":\t\t{Environment.OSVersion.Platform}");
        if (!string.IsNullOrEmpty(Environment.OSVersion.ServicePack))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Service Pack");
            Console.ResetColor();
            Console.WriteLine($":\t\t{Environment.OSVersion.ServicePack}");
        }
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Windows Shell");
        Console.ResetColor();
        Console.WriteLine($":\t\t{GetWindowsShell()}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Windows Directory");
        Console.ResetColor();
        Console.WriteLine($":\t{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Logical Drives");
        Console.ResetColor();
        Console.WriteLine($":\t\t{GetDiskInformation()}");
        var (ipv4, ipv6) = GetHostIPAddresses(showIPv6);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("IP Addresses");
        Console.ResetColor();
        Console.WriteLine($":\t\t{ipv4 ?? "No IPv4 address found"}\n\t\t\t{ipv6 ?? "No IPv6 address found"}".Trim());
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Display Resolution");
        Console.ResetColor();
        Console.WriteLine($":\t{GetDisplayResolution()}");
        int tickCount = Environment.TickCount;
        TimeSpan uptime = TimeSpan.FromMilliseconds(tickCount);
        string formattedUptime = string.Format("{0} days, {1} hours, {2} minutes, {3} seconds", uptime.Days, uptime.Hours, uptime.Minutes, uptime.Seconds);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Uptime");
        Console.ResetColor();
        Console.WriteLine($":\t\t\t{formattedUptime}");
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplayUserInfo(bool showSpecialDirs)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("User Information");
        Console.ResetColor();
        Console.WriteLine(LineBreak);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("User Name");
        Console.ResetColor();
        Console.WriteLine($":\t\t{Environment.UserName}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("User Domain Name");
        Console.ResetColor();
        Console.WriteLine($":\t{Environment.UserDomainName}");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("Machine Name");
        Console.ResetColor();
        Console.WriteLine($":\t\t{Environment.MachineName}");
        GetUserDirs(showSpecialDirs);
        Console.WriteLine(LineBreak);
        Console.WriteLine();
    }

    public static void DisplayEnvironmentPaths(bool showPaths)
    {
        if (showPaths)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Environment PATHs");
            Console.ResetColor();
            Console.WriteLine(LineBreak);
            // Get user path
            string userPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? string.Empty;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("User PATH");
            Console.ResetColor();
            Console.WriteLine(":");
            string[] userPaths = userPath.Split(';');
            foreach (string path in userPaths)
            {
                Console.WriteLine(path);
            }
            // Get system path
            string systemPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? string.Empty;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("System PATH");
            Console.ResetColor();
            Console.WriteLine(":");
            string[] systemPaths = systemPath.Split(';');
            foreach (string path in systemPaths)
            {
                Console.WriteLine(path);
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
                foreach (ManagementObject obj in searcher.Get())
                {
                    string? manufacturer = obj["Manufacturer"]?.ToString()?.Trim();
                    string? model = obj["Model"]?.ToString()?.Trim();
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
                    // List each CPU on a new line and indent with tabs
                    cpuName += $"{obj["Name"]}\n\t\t\t";
                }
            }
        }
        catch (Exception)
        {
            return "Unknown";
        }
        return cpuName.Trim();
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
                    // List each GPU on a new line and indent with tabs
                    gpuName += $"{obj["Name"]}\n\t\t\t";
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
        ulong totalPhysicalMemory = 0;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    // Check for null and parse the value to ulong or return 0
                    totalPhysicalMemory = obj?["TotalPhysicalMemory"] != null &&
                        ulong.TryParse(obj["TotalPhysicalMemory"].ToString(), out ulong parsedValue)
                        ? parsedValue : 0;
                }
            }
        }
        catch (Exception)
        {
            totalPhysicalMemory = 0;
        }
        return totalPhysicalMemory;
    }

    public static ulong GetFreePhysicalMemory()
    {
        ulong freePhysicalMemory = 0;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT FreePhysicalMemory FROM Win32_OperatingSystem"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    // Convert from kilobytes to bytes
                    // Check for null and parse the value to ulong or return 0
                    freePhysicalMemory = obj?["FreePhysicalMemory"] != null &&
                        ulong.TryParse(obj["FreePhysicalMemory"].ToString(), out ulong parsedValue)
                        ? parsedValue * 1024 : 0;
                }
            }
        }
        catch (Exception)
        {
            freePhysicalMemory = 0;
        }
        return freePhysicalMemory;
    }

    public static string GetBIOSInformation()
    {
        string biosInfo = string.Empty;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"))
            {
                foreach (var obj in searcher.Get())
                {
                    string? manufacturer;
                    string? version;
                    string? releaseDateRaw;
                    string? releaseDate;
                    try
                    {
                        manufacturer = obj["Manufacturer"]?.ToString()?.Trim();
                    }
                    catch (Exception)
                    {
                        manufacturer = String.Empty;
                    }
                    try
                    {
                        version = obj["SMBIOSBIOSVersion"]?.ToString()?.Trim();
                    }
                    catch (Exception)
                    {
                        version = String.Empty;
                    }
                    try
                    {
                        releaseDateRaw = obj["ReleaseDate"]?.ToString()?.Trim();
                        releaseDate = string.Empty;
                        if (!string.IsNullOrEmpty(releaseDateRaw) && releaseDateRaw.Length >= 8)
                        {
                            string year = releaseDateRaw.Substring(0, 4);
                            string month = releaseDateRaw.Substring(4, 2);
                            string day = releaseDateRaw.Substring(6, 2);
                            releaseDate = $"{month}/{day}/{year}"; // Format as MM/DD/YYYY
                        }
                    }
                    catch (Exception)
                    {
                        releaseDate = String.Empty;
                    }
                    if (string.IsNullOrEmpty(manufacturer) && string.IsNullOrEmpty(version) && string.IsNullOrEmpty(releaseDate))
                    {
                        return "Unknown";
                    }
                    // List each version on a new line and indent with tabs
                    biosInfo += $"{manufacturer} {version} {releaseDate}\n\t\t\t";
                }
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving BIOS information: {ex.Message}";
        }
        return biosInfo.Trim();
    }

    public static string GetEmbeddedControllerVersion()
    {
        string ecVersion = string.Empty;
        try
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion FROM Win32_BIOS"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    string? majorVersion;
                    string? minorVersion;
                    try
                    {
                        majorVersion = obj["EmbeddedControllerMajorVersion"]?.ToString()?.Trim();
                    }
                    catch (Exception)
                    {
                        majorVersion = String.Empty;
                    }
                    try
                    {
                        minorVersion = $".{obj["EmbeddedControllerMinorVersion"]?.ToString()?.Trim()}";
                    }
                    catch (Exception)
                    {
                        minorVersion = String.Empty;
                    }
                    if (string.IsNullOrEmpty(majorVersion) && string.IsNullOrEmpty(minorVersion))
                    {
                        return "Unknown";
                    }
                    // List each version on a new line and indent with tabs
                    ecVersion += $"{majorVersion}{minorVersion}\n\t\t\t";
                }
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving EC version: {ex.Message}";
        }
        return ecVersion.Trim();
    }

    public static string GetUEFISecureBoot()
    {
        string UEFISecureBootEnabled = GetRegistryString(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
        if (!string.IsNullOrEmpty(UEFISecureBootEnabled))
        {
            if (UEFISecureBootEnabled == "1")
            {
                return "Enabled";
            }
            else if (UEFISecureBootEnabled == "0")
            {
                return "Disabled";
            }
            else
            {
                return "Not Detected";
            }
        }
        return "Not Supported";
    }

    public static string GetBatteryStatus()
    {
        string batteryInfo = String.Empty;
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    string percentage = "0";
                    string status = "Unknown";
                    try
                    {
                        percentage = obj["EstimatedChargeRemaining"] != null &&
                            int.TryParse(obj["EstimatedChargeRemaining"].ToString(), out int parsedPercentage)
                            ? $"{parsedPercentage}" : "Unknown";
                    }
                    catch (Exception)
                    {
                        percentage = "0";
                    }
                    try
                    {
                        if (obj["BatteryStatus"] != null &&
                            int.TryParse(obj["BatteryStatus"].ToString(), out int parsedStatus))
                        {
                            status = parsedStatus switch
                            {
                                1 => "Discharging",
                                2 => "AC Power",
                                3 => "Fully Charged",
                                4 => "Low",
                                5 => "Critical",
                                6 => "Charging",
                                7 => "Charging and High",
                                8 => "Charging and Low",
                                9 => "Charging and Critical",
                                10 => "Undefined",
                                11 => "Partially Charged",
                                _ => "Unknown"
                            };
                        }
                    }
                    catch (Exception)
                    {
                        status = "Unknown";
                    }
                    // List each battery on a new line and indent with tabs
                    batteryInfo += $"{percentage}% ({status})\n\t\t\t";
                }
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving battery information: {ex.Message}";
        }
        return batteryInfo.Trim();
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

    public static string GetWindowsReleaseVersion()
    {
        string DisplayVersion = GetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion");
        string ReleaseId = GetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId");
        if (!string.IsNullOrEmpty(DisplayVersion))
        {
            return DisplayVersion;
        }
        else if (!string.IsNullOrEmpty(ReleaseId))
        {
            return ReleaseId;
        }
        return "Windows";
    }

    public static string GetUpdateBuildRevision()
    {
        string UBR = GetRegistryString(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
        if (!string.IsNullOrEmpty(UBR))
        {
            return $".{UBR}";
        }
        return "";
    }

    public static string GetWindowsShell()
    {
        try
        {
            int currentProcessId = Process.GetCurrentProcess().Id;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {currentProcessId}");
            foreach (ManagementObject obj in searcher.Get())
            {
                int parentProcessId = Convert.ToInt32(obj["ParentProcessId"]);
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
        string driveInfo = String.Empty;
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT DeviceID, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3");
            foreach (ManagementObject obj in searcher.Get())
            {
                string? driveLetter;
                string? fileSystem;
                ulong totalSpace = 0;
                ulong freeSpace = 0;
                try
                {
                    driveLetter = $"{obj["DeviceID"]?.ToString()}\\";
                }
                catch (Exception)
                {
                    driveLetter = "Unknown Drive";
                }
                try
                {
                    fileSystem = obj["FileSystem"]?.ToString();
                }
                catch (Exception)
                {
                    fileSystem = "Unknown FS";
                }
                try
                {
                    totalSpace = (ulong)obj["Size"] / GibibyteUL;
                }
                catch (Exception)
                {
                    totalSpace = 0;
                }
                try
                {
                    freeSpace = (ulong)obj["FreeSpace"] / GibibyteUL;
                }
                catch (Exception)
                {
                    freeSpace = 0;
                }
                // List each drive on a new line and indent with tabs
                driveInfo += $"{driveLetter} {totalSpace} GiB ({freeSpace} GiB free) - {fileSystem}\n\t\t\t";
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving drive information: {ex.Message}";
        }
        return driveInfo.Trim();
    }

    public static (string, string) GetHostIPAddresses(bool showIPv6)
    {
        string ipv4 = string.Empty;
        string ipv6 = string.Empty;
        try
        {
            string hostName = Dns.GetHostName();
            var ipAddresses = Dns.GetHostAddresses(hostName); // Get all IP addresses for the host
            foreach (var ip in ipAddresses)
            {
                try
                {
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // IPv4
                    {
                        ipv4 += $"{ip.ToString()}\n\t\t\t";
                    }
                }
                catch (Exception ex)
                {
                    ipv4 = $"Error retrieving IPv4: {ex.Message}";
                }
                if (showIPv6)
                {
                    try
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) // IPv6
                        {
                            ipv6 += $"{ip.ToString()}\n\t\t\t";
                        }
                    }
                    catch (Exception ex)
                    {
                        ipv6 = $"Error retrieving IPv6: {ex.Message}";
                    }
                }
            }
        }
        catch (Exception ex)
        {
            ipv4 = $"Error: {ex.Message}";
            ipv6 = showIPv6 ? $"Error: {ex.Message}" : ipv6;
        }
        return (ipv4.Trim(), ipv6.Trim());
    }

    public static string GetDisplayResolution()
    {
        string displayInfo = string.Empty;
        try
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate, CurrentBitsPerPixel FROM Win32_VideoController");
            foreach (ManagementObject obj in searcher.Get())
            {
                string? horizontalResolution;
                string? verticalResolution;
                string? screenResolution;
                string? refreshRate;
                string? bitsPerPixel;
                try
                {
                    horizontalResolution = obj["CurrentHorizontalResolution"]?.ToString();
                    verticalResolution = obj["CurrentVerticalResolution"]?.ToString();
                    screenResolution = $"{horizontalResolution}x{verticalResolution}";
                }
                catch (Exception)
                {
                    screenResolution = "Unknown Resolution";
                }
                try
                {
                    refreshRate = obj["CurrentRefreshRate"]?.ToString();
                }
                catch (Exception)
                {
                    refreshRate = "0";
                }
                try
                {
                    bitsPerPixel = obj["CurrentBitsPerPixel"]?.ToString();
                }
                catch (Exception)
                {
                    bitsPerPixel = "0";
                }
                // List each display on a new line and indent with tabs
                displayInfo += $"{screenResolution} @ {refreshRate} Hz ({bitsPerPixel} BPP)\n\t\t\t";
            }
        }
        catch (Exception ex)
        {
            return $"Error retrieving display information: {ex.Message}";
        }
        return displayInfo.Trim();
    }

    public static void GetUserDirs(bool showSpecialDirs)
    {
        try
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("User Profile");
            Console.ResetColor();
            Console.WriteLine($":\t\t{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}");
            if (showSpecialDirs)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Desktop");
                Console.ResetColor();
                Console.WriteLine($":\t\t{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Documents");
                Console.ResetColor();
                Console.WriteLine($":\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Pictures");
                Console.ResetColor();
                Console.WriteLine($":\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Music");
                Console.ResetColor();
                Console.WriteLine($":\t\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyMusic)}");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.Write("Videos");
                Console.ResetColor();
                Console.WriteLine($":\t\t\t{Environment.GetFolderPath(Environment.SpecialFolder.MyVideos)}");
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Application Data");
            Console.ResetColor();
            Console.WriteLine($":\t{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("Working Directory");
            Console.ResetColor();
            Console.WriteLine($":\t{Environment.CurrentDirectory}");
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("User Profile");
            Console.ResetColor();
            Console.WriteLine($":\t\tError retrieving user profile information: {ex.Message}");
        }
    }

    // Helper Methods
    public static bool IsBatteryPresent()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Battery"))
            {
                var batteries = searcher.Get();
                if (batteries.Count > 0)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string GetRegistryString(string path, string key)
    {
        try
        {
            using (RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(path))
            {
                if (registryKey != null)
                {
                    object? value = registryKey.GetValue(key);
                    if (value is string stringValue)
                    {
                        return stringValue;
                    }
                    if (value is int intValue)
                    {
                        return intValue.ToString();
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

    public static void Exit()
    {
        Console.WriteLine("Press any key to exit.");
        Console.ReadKey(true);
    }
}
