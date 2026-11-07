using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace OpenMount.Core.Monitoring
{
    public class FileAccessEvent
    {
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string Operation { get; set; } = string.Empty;
    }

    public class ProcessAccessMonitor
    {
        private readonly ConcurrentDictionary<int, string> _processNameCache = new ConcurrentDictionary<int, string>();
        private readonly ConcurrentQueue<FileAccessEvent> _events = new ConcurrentQueue<FileAccessEvent>();
        private const int MaxEvents = 200;
        private int _eventCount;
        private int _lastPid;
        private string _lastPath = string.Empty;
        private string _lastOp = string.Empty;
        private long _lastEventTicksUtc;

        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        public bool IsEnabled { get; set; }

        public ProcessAccessMonitor(bool isEnabled = false)
        {
            IsEnabled = isEnabled;
        }

        public void RecordAccess(int processId, string filePath, string operation)
        {
            if (!IsEnabled || processId <= 0) return;

            long nowTicks = DateTime.UtcNow.Ticks;
            if (processId == _lastPid &&
                nowTicks - Interlocked.Read(ref _lastEventTicksUtc) < TimeSpan.TicksPerSecond &&
                string.Equals(operation, _lastOp, StringComparison.Ordinal) &&
                string.Equals(filePath, _lastPath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _lastPid = processId;
            _lastPath = filePath;
            _lastOp = operation;
            Interlocked.Exchange(ref _lastEventTicksUtc, nowTicks);

            string procName = GetProcessName(processId);
            var evt = new FileAccessEvent
            {
                TimestampUtc = new DateTime(nowTicks, DateTimeKind.Utc),
                ProcessId = processId,
                ProcessName = procName,
                FilePath = filePath,
                Operation = operation
            };

            _events.Enqueue(evt);
            int count = Interlocked.Increment(ref _eventCount);
            while (count > MaxEvents && _events.TryDequeue(out _))
            {
                count = Interlocked.Decrement(ref _eventCount);
            }
        }

        public string GetProcessName(int processId)
        {
            if (processId <= 4) return "System";

            return _processNameCache.GetOrAdd(processId, static pid =>
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (hProcess != IntPtr.Zero)
                {
                    try
                    {
                        var sb = new StringBuilder(260);
                        uint size = (uint)sb.Capacity;
                        if (QueryFullProcessImageNameW(hProcess, 0, sb, ref size) && size > 0)
                        {
                            return Path.GetFileNameWithoutExtension(sb.ToString());
                        }
                    }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }

                try
                {
                    using var p = Process.GetProcessById(pid);
                    return p.ProcessName;
                }
                catch
                {
                    return $"PID:{pid}";
                }
            });
        }

        public bool IsPreviewProcess(int processId)
        {
            string name = GetProcessName(processId);
            return name.Equals("prevhost", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("thumbnailhost", StringComparison.OrdinalIgnoreCase) ||
                   name.Equals("SearchProtocolHost", StringComparison.OrdinalIgnoreCase);
        }

        public FileAccessEvent[] GetRecentEvents()
        {
            return _events.ToArray();
        }

        public void Clear()
        {
            while (_events.TryDequeue(out _))
            {
                Interlocked.Decrement(ref _eventCount);
            }
        }
    }
}
