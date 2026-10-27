// SPDX-License-Identifier: GPL-3.0-only
// Based on LuSlower/chiptool: https://github.com/LuSlower/chiptool
// Original assembly notice: Copyright ©  2025
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Chiptool
{
    internal sealed class UsageException : Exception
    {
        internal UsageException(string message) : base(message) { }
    }

    internal sealed class HardwareException : Exception
    {
        internal HardwareException(string message) : base(message) { }
    }

    internal enum Space { Msr, Pci, Io, Memory, Pmc, Block }

    internal sealed class BitField
    {
        internal readonly int Low;
        internal readonly int Width;
        internal readonly ulong ValueMask;
        internal readonly ulong RegisterMask;

        internal BitField(string text, int registerWidth)
        {
            string[] parts = text.Split(':');
            int a, b;
            if (parts.Length < 1 || parts.Length > 2 ||
                !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out a))
                throw new UsageException("Use bit or high:low.");
            b = a;
            if (parts.Length == 2 && !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out b))
                throw new UsageException("Use bit or high:low.");
            if (a < 0 || b < 0 || a >= registerWidth || b >= registerWidth)
                throw new UsageException("Bit range exceeds " + registerWidth + "-bit register.");
            Low = Math.Min(a, b);
            Width = Math.Abs(a - b) + 1;
            ValueMask = Mask(Width);
            RegisterMask = ValueMask << Low;
        }

        internal static ulong Mask(int width) { return width == 64 ? ulong.MaxValue : (1UL << width) - 1; }
        internal ulong Extract(ulong value) { return (value >> Low) & ValueMask; }
        internal ulong Insert(ulong original, ulong value)
        {
            if (value > ValueMask) throw new UsageException("Value does not fit the bit range.");
            return (original & ~RegisterMask) | (value << Low);
        }
        public override string ToString() { return Width == 1 ? Low.ToString(CultureInfo.InvariantCulture) : (Low + Width - 1) + ":" + Low; }
    }

    internal sealed class Command
    {
        internal Space Space;
        internal bool Write, AllCpus;
        internal int Width = 64, Cpu, Bus, Device, Function;
        internal ulong Address, Value;
        internal BitField Field;
        internal byte[] Bytes;
        internal int Count;

        internal static ulong Hex(string text, ulong maximum, string name)
        {
            string digits = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? text.Substring(2) : text;
            ulong value;
            if (digits.Length == 0 || !ulong.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out value) || value > maximum)
                throw new UsageException(name + ": use hex 0x0..0x" + maximum.ToString("X", CultureInfo.InvariantCulture) + ".");
            return value;
        }

        private static int Decimal(string text, int minimum, int maximum, string name)
        {
            int value;
            if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) || value < minimum || value > maximum)
                throw new UsageException(name + ": use decimal " + minimum + ".." + maximum + ".");
            return value;
        }

        internal static Command Parse(string[] arguments)
        {
            var args = new List<string>();
            var c = new Command();
            bool cpuSpecified = false;
            foreach (string arg in arguments) if (arg == null) throw new UsageException("Null argument.");
            for (int i = 0; i < arguments.Length; ++i)
            {
                string arg = arguments[i].ToLowerInvariant();
                if (arg == "--cpu")
                {
                    if (cpuSpecified || ++i == arguments.Length) throw new UsageException("Use --cpu <index|all> once.");
                    cpuSpecified = true;
                    c.AllCpus = string.Equals(arguments[i], "all", StringComparison.OrdinalIgnoreCase);
                    if (!c.AllCpus) c.Cpu = Decimal(arguments[i], 0, int.MaxValue, "CPU index");
                }
                else args.Add(arguments[i]);
            }
            if (args.Count == 0) throw new UsageException("Missing command.");
            string name = args[0].ToLowerInvariant();
            if (name.StartsWith("--", StringComparison.Ordinal)) name = name.Substring(2);
            switch (name)
            {
                case "rdmsr": case "wrmsr": case "rdmsrb": case "wrmsrb": c.Space = Space.Msr; break;
                case "rdpci": case "wrpci": case "rdpcib": case "wrpcib": c.Space = Space.Pci; break;
                case "rdio": case "wrio": case "rdiob": case "wriob": c.Space = Space.Io; break;
                case "rdmem": case "wrmem": case "rdmemb": case "wrmemb": c.Space = Space.Memory; break;
                case "rdmemblk": case "wrmemblk": c.Space = Space.Block; break;
                case "rdpmc": c.Space = Space.Pmc; break;
                default: throw new UsageException("Unknown command '" + args[0] + "'. Use --help.");
            }
            c.Write = name.StartsWith("wr", StringComparison.Ordinal);
            bool bits = name.EndsWith("b", StringComparison.Ordinal);
            if (cpuSpecified && c.Space != Space.Msr && c.Space != Space.Pmc)
                throw new UsageException("--cpu is only for MSR/PMC.");
            if (!cpuSpecified && name == "wrmsrb") c.AllCpus = true;
            int expected = c.Space == Space.Pci ? 4 : c.Space == Space.Io || c.Space == Space.Memory || c.Space == Space.Block ? 3 : 2;
            if (bits) ++expected;
            if (c.Write && c.Space != Space.Block) expected += name == "wrmsr" ? 2 : 1;
            if (c.Space != Space.Block || !c.Write)
                if (args.Count != expected) throw new UsageException("Wrong arguments for --" + name + ". Use --help.");
            if (c.Space == Space.Block && c.Write && args.Count < 3)
                throw new UsageException("Use --wrmemblk <decimal-count> <address> <bytes...>.");
            int p = 1;
            if (c.Space == Space.Block)
            {
                c.Count = Decimal(args[p++], 1, 3584, "Block byte count");
                c.Width = 8;
                c.Address = Hex(args[p++], 0xFFFFFFFFFFFFFUL, "Physical address");
                if (c.Address > 0xFFFFFFFFFFFFFUL - (ulong)(c.Count - 1)) throw new UsageException("Block exceeds the address limit.");
                if (c.Write)
                {
                    if (args.Count != 3 + c.Count) throw new UsageException("Byte count does not match the data.");
                    c.Bytes = new byte[c.Count];
                    for (int i = 0; i < c.Count; ++i) c.Bytes[i] = (byte)Hex(args[p++], 255, "Byte");
                }
                return c;
            }
            if (c.Space == Space.Pci || c.Space == Space.Io || c.Space == Space.Memory)
            {
                c.Width = Decimal(args[p++], 8, c.Space == Space.Memory ? 64 : 32, "Register width");
                if (c.Width != 8 && c.Width != 16 && c.Width != 32 && c.Width != 64)
                    throw new UsageException("Width: 8, 16, 32; memory also supports 64.");
            }
            if (c.Space == Space.Pci)
            {
                string[] bdf = args[p++].Split(':');
                if (bdf.Length != 3) throw new UsageException("Use PCI bus:device:function in hex.");
                c.Bus = (int)Hex(bdf[0], 255, "PCI bus");
                c.Device = (int)Hex(bdf[1], 31, "PCI device");
                c.Function = (int)Hex(bdf[2], 7, "PCI function");
                c.Address = Hex(args[p++], 4095, "PCI offset");
                if (c.Address % (ulong)(c.Width / 8) != 0 || c.Address + (ulong)(c.Width / 8) > 4096)
                    throw new UsageException("PCI offset must be aligned and within 0x0..0xFFF.");
            }
            else
            {
                ulong max = c.Space == Space.Io ? 65535UL : c.Space == Space.Memory ? 0xFFFFFFFFFFFFFUL : uint.MaxValue;
                c.Address = Hex(args[p++], max, c.Space == Space.Io ? "Port" : "Address/index");
                if ((c.Space == Space.Io || c.Space == Space.Memory) && c.Address > max - (ulong)(c.Width / 8 - 1))
                    throw new UsageException("Access exceeds the address limit.");
                if (c.Space == Space.Memory && c.Address % (ulong)(c.Width / 8) != 0)
                    throw new UsageException("Unaligned address. Use byte or block access.");
            }
            if (bits) c.Field = new BitField(args[p++], c.Width);
            if (c.Write)
            {
                if (name == "wrmsr")
                    c.Value = (Hex(args[p++], uint.MaxValue, "EDX") << 32) | Hex(args[p++], uint.MaxValue, "EAX");
                else c.Value = Hex(args[p++], c.Field == null ? BitField.Mask(c.Width) : c.Field.ValueMask, "Value");
            }
            return c;
        }

        internal string Target()
        {
            string target = Space == Space.Pci
                ? string.Format(CultureInfo.InvariantCulture, "{0:X2}:{1:X2}:{2:X} 0x{3:X}", Bus, Device, Function, Address)
                : "0x" + Address.ToString("X", CultureInfo.InvariantCulture);
            return target + (Field == null ? "" : " " + Field);
        }

        internal string Location(int cpu = -1)
        {
            string area = Space == Space.Msr ? "MSR" : Space == Space.Pci ? "PCI" : Space == Space.Io ? "IO" : Space == Space.Pmc ? "PMC" : "MEM";
            return (Write ? "wr" : "rd") + area + (cpu < 0 ? "" : " cpu" + cpu) + " " + Target() +
                (Space == Space.Block ? " " + Count + " bytes" : "");
        }
    }

    internal interface IHardware : IDisposable
    {
        int CpuCount { get; }
        ulong Read(Command command, int cpu);
        void Write(Command command, int cpu, ulong value);
        byte[] ReadBlock(Command command);
        void WriteBlock(Command command);
    }

    internal static class Engine
    {
        private static string Bytes(byte[] data, int start, int count, bool hex)
        {
            var result = new StringBuilder();
            for (int i = start; i < start + count; ++i)
            {
                if (i > start) result.Append(' ');
                if (hex) result.Append("0x");
                result.Append(data[i].ToString(hex ? "X" : "D", CultureInfo.InvariantCulture));
            }
            return result.ToString();
        }

        internal static void Execute(Command c, IHardware hardware, TextWriter output)
        {
            bool perCpu = c.Space == Space.Msr || c.Space == Space.Pmc;
            if (perCpu && (hardware.CpuCount < 1 || (!c.AllCpus && c.Cpu >= hardware.CpuCount)))
                throw new UsageException("CPU must be 0.." + (hardware.CpuCount - 1) + ".");
            if (c.Space == Space.Block)
            {
                if (c.Write)
                {
                    hardware.WriteBlock(c);
                    output.WriteLine("[+] {0} {1}", c.Target(), Bytes(c.Bytes, 0, c.Count, true));
                }
                else
                {
                    byte[] data = hardware.ReadBlock(c);
                    for (int i = 0; i < data.Length; i += 16)
                    {
                        int length = Math.Min(16, data.Length - i);
                        output.WriteLine(Bytes(data, i, length, true));
                        output.WriteLine(Bytes(data, i, length, false));
                    }
                }
                return;
            }
            int count = perCpu && c.AllCpus ? hardware.CpuCount : 1;
            for (int i = 0; i < count; ++i)
            {
                int cpu = c.AllCpus ? i : c.Cpu;
                string location = c.Location(perCpu ? cpu : -1);
                ulong value;
                try
                {
                    if (c.Write)
                    {
                        value = c.Field == null ? c.Value : c.Field.Insert(hardware.Read(c, cpu), c.Value);
                        hardware.Write(c, cpu, value);
                    }
                    else
                    {
                        value = hardware.Read(c, cpu);
                        if (c.Field != null) value = c.Field.Extract(value);
                    }
                }
                catch (HardwareException ex)
                {
                    throw new HardwareException(location + ": " + ex.Message + (c.Write && i > 0 ? " Earlier CPUs were written." : ""));
                }
                if (!c.Write)
                {
                    output.WriteLine("0x{0:X}", value);
                    output.WriteLine(value.ToString(CultureInfo.InvariantCulture));
                    output.Flush();
                }
            }
            if (c.Write) output.WriteLine("[+] {0} 0x{1:X}", c.Target(), c.Value);
        }
    }

    internal static class Embedded
    {
        internal static string Hash(byte[] bytes)
        {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
        }

        internal static byte[] Read(string name)
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (stream == null) throw new HardwareException("Driver data missing. Rebuild chiptool.");
                using (var data = new MemoryStream()) { stream.CopyTo(data); return data.ToArray(); }
            }
        }

        internal static void Save(byte[] bytes, string path)
        {
            string hash = Hash(bytes);
            if (File.Exists(path) && Hash(File.ReadAllBytes(path)) == hash) return;
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            if (Hash(File.ReadAllBytes(path)) != hash) throw new HardwareException(Path.GetFileName(path) + ": file check failed.");
        }

    }
    internal static class Elevation
    {
        internal static bool IsAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        internal static string QuoteArgument(string value)
        {
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\') { ++slashes; continue; }
                if (ch == '"') { result.Append('\\', slashes * 2 + 1); result.Append(ch); }
                else { result.Append('\\', slashes); result.Append(ch); }
                slashes = 0;
            }
            result.Append('\\', slashes * 2); result.Append('"');
            return result.ToString();
        }

        internal static int Elevate(string[] args)
        {
            var commandLine = new StringBuilder();
            foreach (string arg in args) { if (commandLine.Length > 0) commandLine.Append(' '); commandLine.Append(QuoteArgument(arg)); }
            using (Process child = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, commandLine.ToString())
            { UseShellExecute = true, Verb = "runas", WorkingDirectory = Environment.CurrentDirectory }))
            {
                if (child == null) throw new HardwareException("Elevation failed.");
                child.WaitForExit();
                return child.ExitCode;
            }
        }
    }

    internal sealed class CpuAffinity : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct GroupAffinity { internal UIntPtr Mask; internal ushort Group, Reserved0, Reserved1, Reserved2; }
        private GroupAffinity previous;
        private bool active;
        [DllImport("kernel32.dll", ExactSpelling = true)] private static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int SetThreadGroupAffinity(IntPtr thread, ref GroupAffinity affinity, out GroupAffinity old);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int GetLogicalProcessorInformationEx(int relationship, [Out] byte[] buffer, ref uint length);

        internal static List<GroupAffinity> Targets()
        {
            uint length = 0;
            GetLogicalProcessorInformationEx(4, null, ref length);
            if (length < 32 || length > 1048576) throw new HardwareException("CPU query failed.");
            byte[] data = new byte[length];
            if (GetLogicalProcessorInformationEx(4, data, ref length) == 0) throw new HardwareException("CPU query failed: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
            return DecodeTargets(data);
        }

        internal static List<GroupAffinity> DecodeTargets(byte[] data)
        {
            if (data.Length < 32 || BitConverter.ToUInt32(data, 0) != 4) throw new HardwareException("Invalid CPU data.");
            int groups = BitConverter.ToUInt16(data, 10);
            uint size = BitConverter.ToUInt32(data, 4);
            if (groups < 1 || size > data.Length || size < 32 + groups * 48) throw new HardwareException("Incomplete CPU data.");
            var targets = new List<GroupAffinity>();
            for (int group = 0; group < groups; ++group)
            {
                int start = 32 + group * 48, count = 0;
                ulong mask = BitConverter.ToUInt64(data, start + 40);
                for (int bit = 0; bit < 64; ++bit)
                    if ((mask & (1UL << bit)) != 0) { targets.Add(new GroupAffinity { Group = (ushort)group, Mask = (UIntPtr)(1UL << bit) }); ++count; }
                if (count != data[start + 1]) throw new HardwareException("CPU mask/count mismatch.");
            }
            if (targets.Count == 0) throw new HardwareException("No active CPUs.");
            return targets;
        }

        internal CpuAffinity(GroupAffinity target)
        {
            Thread.BeginThreadAffinity();
            if (SetThreadGroupAffinity(GetCurrentThread(), ref target, out previous) == 0)
            {
                int error = Marshal.GetLastWin32Error(); Thread.EndThreadAffinity();
                throw new HardwareException("Cannot select CPU: " + new Win32Exception(error).Message);
            }
            active = true;
        }
        public void Dispose()
        {
            if (!active) return;
            active = false;
            GroupAffinity ignored;
            int success = SetThreadGroupAffinity(GetCurrentThread(), ref previous, out ignored);
            int error = success == 0 ? Marshal.GetLastWin32Error() : 0;
            Thread.EndThreadAffinity();
            if (success == 0) throw new HardwareException("Cannot restore CPU affinity: " + new Win32Exception(error).Message);
        }
    }

    internal sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private ServiceHandle() : base(true) { }
        [DllImport("advapi32.dll", ExactSpelling = true)] private static extern int CloseServiceHandle(IntPtr handle);
        protected override bool ReleaseHandle() { return CloseServiceHandle(handle) != 0; }
    }

    internal sealed class KernelDriver : IDisposable
    {
        private readonly string name, devicePath, fileName, resource, hash, serviceName;
        private readonly bool countUsers;
        private SafeFileHandle handle;
        private ServiceHandle service;
        private bool disposed, startedHere;
        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatus { internal uint Type, State, Controls, Win32Exit, ServiceExit, Checkpoint, WaitHint; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern ServiceHandle OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern ServiceHandle CreateServiceW(ServiceHandle manager, string name, string displayName, uint access,
            uint type, uint start, uint errorControl, string binary, string group, IntPtr tag, string dependencies, string account, string password);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern int ChangeServiceConfigW(ServiceHandle service, uint type, uint start, uint errorControl,
            string binary, string group, IntPtr tag, string dependencies, string account, string password, string displayName);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern int StartServiceW(ServiceHandle service, uint count, IntPtr arguments);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int QueryServiceStatus(ServiceHandle service, out ServiceStatus status);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int ControlService(ServiceHandle service, uint control, out ServiceStatus status);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern int DeviceIoControl(SafeFileHandle device, uint code, [In] byte[] input, uint inputBytes,
            [Out] byte[] output, uint outputBytes, out uint returnedBytes, IntPtr overlapped);


        internal KernelDriver(string name, string devicePath, string fileName, string resource, string hash, bool countUsers)
        {
            this.name = name;
            this.devicePath = devicePath;
            this.fileName = fileName;
            this.resource = resource;
            this.hash = hash;
            this.countUsers = countUsers;
            serviceName = "chiptool_" + name;
            Lifecycle(delegate
            {
                try
                {
                    handle = OpenDevice();
                    int openError = handle.IsInvalid ? Marshal.GetLastWin32Error() : 0;
                    using (ServiceHandle manager = OpenSCManagerW(null, null, 3))
                    {
                        if (manager.IsInvalid) throw SystemError("Driver manager");
                        service = OpenServiceW(manager, serviceName, 0x36);
                        if (service.IsInvalid)
                        {
                            int error = Marshal.GetLastWin32Error();
                            service.Dispose(); service = null;
                            if (error != 1060) throw new HardwareException(name + " service: " + new Win32Exception(error).Message + " (" + error + ").");
                        }
                        if (handle.IsInvalid)
                        {
                            handle.Dispose(); handle = null;
                            if (openError != 2 && openError != 3 && openError != 1167)
                                throw new HardwareException(name + " open failed (" + openError + ").");
                            string path = PrepareDriver();
                            if (service == null)
                            {
                                service = CreateServiceW(manager, serviceName, "chiptool " + name, 0x36, 1, 3, 1, path, null, IntPtr.Zero, null, null, null);
                                if (service.IsInvalid) throw SystemError(name + " service");
                            }
                            else
                            {
                                var timer = Stopwatch.StartNew();
                                ServiceStatus status;
                                for (;;)
                                {
                                    if (QueryServiceStatus(service, out status) == 0) throw SystemError(name + " status");
                                    if (status.State != 3 || timer.ElapsedMilliseconds >= 5000) break;
                                    Thread.Sleep(50);
                                }
                                if (status.State != 1) throw new HardwareException(name + " is busy.");
                                if (ChangeServiceConfigW(service, 1, 3, 1, path, null, IntPtr.Zero, null, null, null, null) == 0)
                                    throw SystemError(name + " setup");
                            }
                            if (StartServiceW(service, 0, IntPtr.Zero) == 0)
                            {
                                int error = Marshal.GetLastWin32Error();
                                if (error != 1056) throw new HardwareException(name + " load failed: " + new Win32Exception(error).Message + " (" + error + ").");
                            }
                            else startedHere = true;
                            handle = OpenDevice();
                            if (handle.IsInvalid) throw SystemError(name + " open");
                            RemoveLegacyDriver();
                        }
                        else if (service != null)
                        {
                            ServiceStatus status;
                            if (QueryServiceStatus(service, out status) == 0 || status.State != 4) { service.Dispose(); service = null; }
                        }
                    }
                }
                catch { Close(); throw; }
            });
        }

        private static HardwareException SystemError(string operation)
        {
            int error = Marshal.GetLastWin32Error();
            return new HardwareException(operation + ": " + new Win32Exception(error).Message + " (" + error + ").");
        }
        private SafeFileHandle OpenDevice() { return CreateFileW(devicePath, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero); }
        private void Lifecycle(Action action)
        {
            using (Mutex mutex = Program.CreateLock(@"Global\chiptool." + name + ".lifecycle.v1"))
            {
                bool held = false;
                try
                {
                    try { held = mutex.WaitOne(TimeSpan.FromSeconds(30)); } catch (AbandonedMutexException) { held = true; }
                    if (!held) throw new HardwareException(name + " is busy.");
                    action();
                }
                finally { if (held) mutex.ReleaseMutex(); }
            }
        }
        private string PrepareDriver()
        {
            byte[] bytes = Embedded.Read(resource);
            if (Embedded.Hash(bytes) != hash) throw new HardwareException(name + " payload hash mismatch.");
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "chiptool");
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (WellKnownSidType type in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(type, null), FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(directory, security);
            byte[] license = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Embedded.Read("chiptool.license")) + "\n\n" +
                Encoding.UTF8.GetString(Embedded.Read("chiptool.notices")));
            Embedded.Save(license, Path.Combine(directory, "LICENSE.txt"));
            string path = Path.Combine(directory, fileName);
            Embedded.Save(bytes, path);
            return path;
        }
        private void RemoveLegacyDriver()
        {
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "chiptool-drivers");
            string directory = Path.Combine(root, hash);
            string path = Path.Combine(directory, name == "WinRing0" ? "WinRing0x64.sys" : "inpoutx64.sys");
            try
            {
                if (!Directory.Exists(directory) || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0 ||
                    (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) return;
                if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0 && Embedded.Hash(File.ReadAllBytes(path)) == hash)
                    File.Delete(path);
                if (Directory.GetFileSystemEntries(directory).Length == 0) Directory.Delete(directory);
                if (Directory.GetFileSystemEntries(root).Length == 0) Directory.Delete(root);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        internal byte[] Control(uint code, byte[] input, int outputSize)
        {
            byte[] output = new byte[outputSize]; uint received;
            if (DeviceIoControl(handle, code, input, (uint)input.Length, output, (uint)output.Length, out received, IntPtr.Zero) == 0)
                throw SystemError(name);
            if (received != outputSize) throw new HardwareException(name + ": " + received + "/" + outputSize + " bytes received.");
            return output;
        }
        private void Close()
        {
            bool last = !countUsers && startedHere;
            if (handle != null && !handle.IsInvalid && !handle.IsClosed)
            {
                if (countUsers)
                {
                    uint received; byte[] count = new byte[4];
                    last = DeviceIoControl(handle, (40000U << 16) | (0x801U << 2), new byte[0], 0, count, 4, out received, IntPtr.Zero) != 0 &&
                        received == 4 && BitConverter.ToUInt32(count, 0) == 1;
                }
                handle.Dispose();
            }
            else
            {
                if (handle != null) handle.Dispose();
                if (startedHere) last = true;
            }
            if (service != null)
            {
                if (last && !service.IsInvalid)
                {
                    ServiceStatus ignored;
                    if (ControlService(service, 1, out ignored) == 0)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error != 1062) Console.Error.WriteLine("[!] " + name + " stop failed (" + error + ").");
                    }
                }
                service.Dispose(); service = null;
            }
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            Lifecycle(Close);
        }
    }

    internal sealed class MemoryView : SafeHandleZeroOrMinusOneIsInvalid
    {
        private IntPtr section;
        private readonly int offset;
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtUnmapViewOfSection(IntPtr process, IntPtr address);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern int CloseHandle(IntPtr handle);

        internal MemoryView(byte[] result, int offset, int length) : base(true)
        {
            this.offset = offset;
            section = new IntPtr(BitConverter.ToInt64(result, 0));
            SetHandle(new IntPtr(BitConverter.ToInt64(result, 24)));
            if (section == IntPtr.Zero || section == new IntPtr(-1) || handle.ToInt64() <= 0 ||
                handle.ToInt64() > 0x00007FFFFFFFFFFF - offset - length)
            {
                if (IsInvalid && section != IntPtr.Zero && section != new IntPtr(-1))
                {
                    CloseHandle(section);
                    section = IntPtr.Zero;
                }
                Dispose();
                throw new HardwareException("Invalid memory mapping.");
            }
        }
        private IntPtr Address { get { return IntPtr.Add(handle, offset); } }
        internal ulong Read(int width)
        {
            switch (width)
            {
                case 8: return Marshal.ReadByte(Address);
                case 16: return unchecked((ushort)Marshal.ReadInt16(Address));
                case 32: return unchecked((uint)Marshal.ReadInt32(Address));
                case 64: return unchecked((ulong)Marshal.ReadInt64(Address));
                default: throw new UsageException("Invalid memory width.");
            }
        }
        internal void Write(int width, ulong value)
        {
            switch (width)
            {
                case 8: Marshal.WriteByte(Address, (byte)value); break;
                case 16: Marshal.WriteInt16(Address, unchecked((short)value)); break;
                case 32: Marshal.WriteInt32(Address, unchecked((int)value)); break;
                case 64: Marshal.WriteInt64(Address, unchecked((long)value)); break;
                default: throw new UsageException("Invalid memory width.");
            }
        }
        internal byte[] ReadBytes(int count)
        {
            byte[] data = new byte[count];
            for (int i = 0; i < count; ++i) data[i] = Marshal.ReadByte(Address, i);
            return data;
        }
        internal void WriteBytes(byte[] data)
        {
            for (int i = 0; i < data.Length; ++i) Marshal.WriteByte(Address, i, data[i]);
        }
        protected override bool ReleaseHandle()
        {
            int status = NtUnmapViewOfSection(new IntPtr(-1), handle);
            int closed = CloseHandle(section);
            section = IntPtr.Zero;
            return status >= 0 && closed != 0;
        }
    }

    internal sealed class PhysicalMemory : IHardware
    {
        public int CpuCount { get { return 1; } }
        private readonly KernelDriver driver = new KernelDriver("InpOut", @"\\.\inpoutx64", "inpout.sys", "chiptool.inpout",
            "F8965FDCE668692C3785AFA3559159F9A18287BC0D53ABB21902895A8ECF221B", false);
        private MemoryView Map(ulong address, int count)
        {
            int offset = (int)(address & 0xFFF);
            ulong size = (ulong)((offset + count + 0xFFF) & ~0xFFF);
            byte[] input = new byte[32];
            Buffer.BlockCopy(BitConverter.GetBytes(size), 0, input, 8, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(address & ~0xFFFUL), 0, input, 16, 8);
            return new MemoryView(driver.Control((40000U << 16) | (0x807U << 2), input, 32), offset, count);
        }
        public ulong Read(Command command, int cpu)
        {
            using (MemoryView view = Map(command.Address, command.Width / 8)) return view.Read(command.Width);
        }
        public void Write(Command command, int cpu, ulong value)
        {
            using (MemoryView view = Map(command.Address, command.Width / 8)) view.Write(command.Width, value);
        }
        public byte[] ReadBlock(Command command)
        {
            using (MemoryView view = Map(command.Address, command.Count)) return view.ReadBytes(command.Count);
        }
        public void WriteBlock(Command command)
        {
            using (MemoryView view = Map(command.Address, command.Bytes.Length)) view.WriteBytes(command.Bytes);
        }
        public void Dispose() { driver.Dispose(); }
    }

    internal sealed class WinRingHardware : IHardware
    {
        private readonly KernelDriver driver;
        private readonly List<CpuAffinity.GroupAffinity> targets;
        public int CpuCount { get { return targets.Count; } }
        internal WinRingHardware()
        {
            targets = CpuAffinity.Targets();
            driver = new KernelDriver("WinRing0", @"\\.\WinRing0_1_2_0", "winring.sys", "chiptool.winring",
                "11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5", true);
            try { Transfer(0x800, 0, new byte[0], 4); }
            catch { driver.Dispose(); throw; }
        }
        private byte[] Transfer(uint function, uint access, byte[] input, int outputSize)
        {
            return driver.Control((40000U << 16) | (access << 14) | (function << 2), input, outputSize);
        }
        internal static byte[] MsrWriteRequest(uint index, ulong value)
        {
            // OLS_WRITE_MSR_INPUT is explicitly packed to four bytes: uint32 index then uint64 value.
            byte[] request = new byte[12];
            Buffer.BlockCopy(BitConverter.GetBytes(index), 0, request, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes(value), 0, request, 4, 8);
            return request;
        }
        private static byte[] PciRequest(Command c, bool write, ulong value)
        {
            byte[] request = new byte[8 + (write ? c.Width / 8 : 0)];
            uint bdf = ((uint)c.Bus << 8) | ((uint)c.Device << 3) | (uint)c.Function;
            Buffer.BlockCopy(BitConverter.GetBytes(bdf), 0, request, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)c.Address), 0, request, 4, 4);
            if (write) Buffer.BlockCopy(BitConverter.GetBytes(value), 0, request, 8, c.Width / 8);
            return request;
        }
        public ulong Read(Command c, int cpu)
        {
            if (c.Space == Space.Msr || c.Space == Space.Pmc)
            {
                using (var affinity = new CpuAffinity(targets[cpu]))
                    return BitConverter.ToUInt64(Transfer(c.Space == Space.Msr ? 0x821U : 0x823U, 0, BitConverter.GetBytes((uint)c.Address), 8), 0);
            }
            if (c.Space == Space.Pci)
            {
                byte[] value = new byte[8];
                byte[] response = Transfer(0x851, 1, PciRequest(c, false, 0), c.Width / 8);
                Buffer.BlockCopy(response, 0, value, 0, response.Length);
                return BitConverter.ToUInt64(value, 0);
            }
            if (c.Space == Space.Io)
                return BitConverter.ToUInt32(Transfer(c.Width == 8 ? 0x833U : c.Width == 16 ? 0x834U : 0x835U, 1,
                    BitConverter.GetBytes((uint)c.Address), 4), 0) & BitField.Mask(c.Width);
            throw new UsageException("Unsupported WinRing0 command.");
        }
        public void Write(Command c, int cpu, ulong value)
        {
            if (c.Space == Space.Msr)
            {
                using (var affinity = new CpuAffinity(targets[cpu])) Transfer(0x822, 0, MsrWriteRequest((uint)c.Address, value), 0);
                return;
            }
            if (c.Space == Space.Pci) { Transfer(0x852, 2, PciRequest(c, true, value), 0); return; }
            if (c.Space == Space.Io)
            {
                byte[] request = new byte[8];
                Buffer.BlockCopy(BitConverter.GetBytes((uint)c.Address), 0, request, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes((uint)value), 0, request, 4, 4);
                Transfer(c.Width == 8 ? 0x836U : c.Width == 16 ? 0x837U : 0x838U, 2, request, 0); return;
            }
            throw new UsageException("Unsupported WinRing0 command.");
        }
        public byte[] ReadBlock(Command c) { throw new UsageException("Unsupported WinRing0 command."); }
        public void WriteBlock(Command c) { throw new UsageException("Unsupported WinRing0 command."); }

        public void Dispose() { driver.Dispose(); }
    }
    internal static class Program
    {
        private const string Help = @"MSR
  --rdmsr    <msr>
  --wrmsr    <msr> <edx> <eax>
  --rdmsrb   <msr> <bits>
  --wrmsrb   <msr> <bits> <value>

PCI
  --rdpci    <size> <bus:dev:func> <offset>
  --wrpci    <size> <bus:dev:func> <offset> <value>
  --rdpcib   <size> <bus:dev:func> <offset> <bits>
  --wrpcib   <size> <bus:dev:func> <offset> <bits> <value>

I/O
  --rdio     <size> <port>
  --wrio     <size> <port> <value>
  --rdiob    <size> <port> <bits>
  --wriob    <size> <port> <bits> <value>

Memory
  --rdmem    <size> <address>
  --wrmem    <size> <address> <value>
  --rdmemb   <size> <address> <bits>
  --wrmemb   <size> <address> <bits> <value>
  --rdmemblk <count> <address>
  --wrmemblk <count> <address> <bytes...>

CPU
  --rdpmc    <index>
  --cpu      <index|all>";

        private static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0) { Console.WriteLine("chiptool --help"); return 0; }
                if (args.Length == 1 && (args[0] == "--help" || args[0] == "--h" || args[0] == "/?"))
                { Console.WriteLine(Help); return 0; }
                Command c = Command.Parse(args);
                if (!Environment.Is64BitProcess) throw new HardwareException("x64 Windows required.");
                if (!Elevation.IsAdmin()) return Elevation.Elevate(args);
                RunLocked(c, Console.Out);
                return 0;
            }
            catch (UsageException ex) { Console.Error.WriteLine("[-] " + ex.Message); return 2; }
            catch (HardwareException ex) { Console.Error.WriteLine("[-] " + ex.Message); return 1; }
            catch (Win32Exception ex) { Console.Error.WriteLine("[-] " + ex.Message); return 1; }
            catch (UnauthorizedAccessException ex) { Console.Error.WriteLine("[-] " + ex.Message); return 1; }
            catch (IOException ex) { Console.Error.WriteLine("[-] " + ex.Message); return 1; }
        }

        internal static Mutex CreateLock(string name = @"Global\chiptool.hardware.v1")
        {
            var security = new MutexSecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (WellKnownSidType type in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid })
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(type, null), MutexRights.FullControl, AccessControlType.Allow));
            bool created;
            return new Mutex(false, name, out created, security);
        }

        private static void RunLocked(Command c, TextWriter output)
        {
            using (Mutex mutex = CreateLock())
            {
                bool held = false;
                try
                {
                    try { held = mutex.WaitOne(TimeSpan.FromSeconds(30)); }
                    catch (AbandonedMutexException) { held = true; }
                    if (!held) throw new HardwareException("chiptool is busy.");
                    using (IHardware hardware = c.Space == Space.Memory || c.Space == Space.Block
                        ? (IHardware)new PhysicalMemory() : new WinRingHardware())
                        Engine.Execute(c, hardware, output);
                }
                finally { if (held) mutex.ReleaseMutex(); }
            }
        }

    }

}
