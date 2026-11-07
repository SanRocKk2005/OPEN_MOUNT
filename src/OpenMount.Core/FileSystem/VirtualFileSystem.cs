using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Fsp;
using Fsp.Interop;
using OpenMount.Core.Cache;
using OpenMount.Core.Manager;
using OpenMount.Core.Monitoring;
using OpenMount.Core.Storage;
using OpenMount.Core.Sync;
using FileInfo = Fsp.Interop.FileInfo;

namespace OpenMount.Core.FileSystem
{
    public class VirtualFileSystem : FileSystemBase
    {
        private readonly IStorageProvider _storage;
        private readonly string _stagingDir;
        private readonly FileCacheManager _cacheManager;
        private readonly DriveConfig _config;
        private readonly AsyncUploadQueue? _asyncUploadQueue;
        private readonly FolderPropertiesCache _folderPropertiesCache;
        private readonly ProcessAccessMonitor _processMonitor;
        private static readonly byte[] DefaultSecurityDescriptor;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, VirtualFileNode> _activeNodes =
            new System.Collections.Concurrent.ConcurrentDictionary<string, VirtualFileNode>(StringComparer.OrdinalIgnoreCase);

        public DriveConfig Config => _config;
        public AsyncUploadQueue? AsyncUploadQueue => _asyncUploadQueue;
        public FolderPropertiesCache FolderPropertiesCache => _folderPropertiesCache;
        public ProcessAccessMonitor ProcessMonitor => _processMonitor;
        public bool IsMounted { get; set; }

        private const uint FILE_WRITE_DATA = 0x0002;
        private const uint FILE_APPEND_DATA = 0x0004;
        private const int StagingBufferSize = 262144; // 256 KB
        private const int RangeReadAheadBytes = 4 * 1024 * 1024; // 4 MB read-ahead window for large remote files

        static VirtualFileSystem()
        {
            DefaultSecurityDescriptor = CreateLeastPrivilegeSecurityDescriptor();
        }

        private static byte[] CreateLeastPrivilegeSecurityDescriptor()
        {
            try
            {
                var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                string userSid = currentUser?.Value ?? "WD";
                // Grant Full Access (FA) to System (SY), Builtin Admins (BA), and Current User (userSid)
                string sddl = $"O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{userSid})";
                var rawSd = new RawSecurityDescriptor(sddl);
                byte[] buffer = new byte[rawSd.BinaryLength];
                rawSd.GetBinaryForm(buffer, 0);
                return buffer;
            }
            catch
            {
                var rawSd = new RawSecurityDescriptor("O:BAG:BAD:(A;;FA;;;OW)(A;;FA;;;BA)");
                byte[] buffer = new byte[rawSd.BinaryLength];
                rawSd.GetBinaryForm(buffer, 0);
                return buffer;
            }
        }

        public VirtualFileSystem(IStorageProvider storage, string? stagingDir = null, FileCacheManager? cacheManager = null, DriveConfig? config = null)
        {
            _storage = storage ?? throw new ArgumentNullException(nameof(storage));
            _config = config ?? new DriveConfig { AsyncUpload = false };
            _stagingDir = stagingDir ?? Path.Combine(Path.GetTempPath(), "OpenMount", "staging");
            if (!Directory.Exists(_stagingDir))
            {
                Directory.CreateDirectory(_stagingDir);
            }
            _cacheManager = cacheManager ?? new FileCacheManager(storage.ProviderId);
            _folderPropertiesCache = new FolderPropertiesCache();
            _processMonitor = new ProcessAccessMonitor(_config.MonitorProcessAccess);
            if (_config.AsyncUpload)
            {
                _asyncUploadQueue = new AsyncUploadQueue(
                    _storage,
                    path =>
                    {
                        if (_cacheManager.TryGetCachedOrStagedFilePath(path, 0, out var localPath) && !string.IsNullOrEmpty(localPath) && File.Exists(localPath))
                        {
                            var fi = new System.IO.FileInfo(localPath);
                            _cacheManager.MarkUploadCompleted(path, fi.Length, fi.LastWriteTimeUtc);
                        }
                    },
                    maxConcurrentWorkers: 2,
                    keepLocalFileAfterUpload: true);
            }
        }

        private static unsafe uint WriteStreamFromIntPtr(Stream stream, IntPtr buffer, uint length)
        {
            if (length == 0) return 0;
            var span = new ReadOnlySpan<byte>((void*)buffer, (int)length);
            stream.Write(span);
            return length;
        }

        private static unsafe uint ReadStreamToIntPtr(Stream stream, IntPtr buffer, uint length)
        {
            if (length == 0) return 0;
            var span = new Span<byte>((void*)buffer, (int)length);
            int totalRead = 0;
            while (totalRead < (int)length)
            {
                int r = stream.Read(span.Slice(totalRead));
                if (r <= 0) break;
                totalRead += r;
            }
            return (uint)totalRead;
        }

        private VirtualFileNode AcquireNode(string path, bool isDir, long size = 0, FileAttributes attrs = FileAttributes.Normal)
        {
            string clean = NormalizePath(path);
            return _activeNodes.AddOrUpdate(
                clean,
                p => new VirtualFileNode(p, isDir, size, attrs) { OpenCount = 1 },
                (p, existing) =>
                {
                    lock (existing.LockObj)
                    {
                        existing.OpenCount++;
                        if (size > 0 && !existing.IsDirectory)
                        {
                            existing.Size = size;
                        }
                        return existing;
                    }
                });
        }

        private void ReleaseNode(VirtualFileNode node)
        {
            lock (node.LockObj)
            {
                node.OpenCount--;
                if (node.OpenCount <= 0)
                {
                    _activeNodes.TryRemove(node.Path, out _);
                    node.ActiveStagingFilePath = null;
                }
            }
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "\\";
            string clean = path.Replace('/', '\\');
            return clean.StartsWith("\\") ? clean : "\\" + clean;
        }

        private int SafeGetOperationProcessId()
        {
            if (!IsMounted)
                return 0;

            if (!_config.MonitorProcessAccess && _config.EnableFilePreview)
                return 0;

            try
            {
                return GetOperationProcessId();
            }
            catch
            {
                return 0;
            }
        }

        private static readonly HashSet<string> ExplorerProbeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "desktop.ini",
            "autorun.inf",
            "folder.ico",
            "folder.gif",
            "folder.jpg",
            "$RECYCLE.BIN",
            "System Volume Information",
            "Thumbs.db",
            ".Trash",
            ".Trash-1000"
        };

        private class CachedMetadata
        {
            public StorageItemMetadata Metadata { get; }
            public DateTime CachedAtUtc { get; }

            public CachedMetadata(StorageItemMetadata metadata)
            {
                Metadata = metadata;
                CachedAtUtc = DateTime.UtcNow;
            }

            public bool IsExpired(TimeSpan ttl) => (DateTime.UtcNow - CachedAtUtc) > ttl;
        }

        private class CachedDirectoryListing
        {
            public HashSet<string> ChildNames { get; }
            public DateTime CachedAtUtc { get; }

            public CachedDirectoryListing(IEnumerable<string> childNames)
            {
                ChildNames = new HashSet<string>(childNames, StringComparer.OrdinalIgnoreCase);
                CachedAtUtc = DateTime.UtcNow;
            }

            public bool IsExpired(TimeSpan ttl) => (DateTime.UtcNow - CachedAtUtc) > ttl;
        }

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, CachedMetadata> _metadataCache =
            new System.Collections.Concurrent.ConcurrentDictionary<string, CachedMetadata>(StringComparer.OrdinalIgnoreCase);

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, CachedDirectoryListing> _directoryListingCache =
            new System.Collections.Concurrent.ConcurrentDictionary<string, CachedDirectoryListing>(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(30);

        private VolumeInfo _cachedVolumeInfo;
        private DateTime _volumeInfoExpiryUtc = DateTime.MinValue;
        private readonly object _volumeInfoLock = new object();

        private static string GetParentPath(string path)
        {
            string clean = NormalizePath(path);
            int lastIdx = clean.LastIndexOf('\\');
            if (lastIdx <= 0) return "\\";
            return clean.Substring(0, lastIdx);
        }

        private void InvalidateCache(string path)
        {
            string clean = NormalizePath(path);
            _metadataCache.TryRemove(clean, out _);
            string parent = GetParentPath(clean);
            _directoryListingCache.TryRemove(parent, out _);
        }

        private void UpdateCacheForUploadedFile(VirtualFileNode node)
        {
            string clean = NormalizePath(node.Path);
            var meta = new StorageItemMetadata
            {
                Path = clean,
                Name = Path.GetFileName(clean),
                IsDirectory = node.IsDirectory,
                Size = node.Size,
                CreatedTime = node.CreationTime,
                LastAccessTime = node.LastAccessTime,
                LastModifiedTime = node.LastWriteTime,
                Attributes = node.Attributes
            };

            _metadataCache[clean] = new CachedMetadata(meta);

            string parent = GetParentPath(clean);
            if (_directoryListingCache.TryGetValue(parent, out var parentListing) && !parentListing.IsExpired(CacheTtl))
            {
                lock (parentListing)
                {
                    parentListing.ChildNames.Add(meta.Name);
                }
            }
        }

        private StorageItemMetadata? GetCachedOrRemoteMetadata(string path)
        {
            string clean = NormalizePath(path);
            if (clean == "\\" || clean == "/")
            {
                return new StorageItemMetadata
                {
                    Path = "\\",
                    Name = "\\",
                    IsDirectory = true,
                    CreatedTime = DateTimeOffset.UtcNow,
                    LastAccessTime = DateTimeOffset.UtcNow,
                    LastModifiedTime = DateTimeOffset.UtcNow,
                    Attributes = FileAttributes.Directory
                };
            }

            // 1. Fast in-memory metadata hit
            if (_metadataCache.TryGetValue(clean, out var cached) && !cached.IsExpired(CacheTtl))
            {
                return cached.Metadata;
            }

            // In-flight Async Upload Queue check (Read-Your-Own-Writes)
            if (_asyncUploadQueue != null && _asyncUploadQueue.TryGetInFlightLocalPath(clean, out var inFlightPath) && File.Exists(inFlightPath))
            {
                var fi = new System.IO.FileInfo(inFlightPath!);
                return new StorageItemMetadata
                {
                    Path = clean,
                    Name = Path.GetFileName(clean),
                    IsDirectory = false,
                    Size = fi.Length,
                    CreatedTime = fi.CreationTimeUtc,
                    LastAccessTime = fi.LastAccessTimeUtc,
                    LastModifiedTime = fi.LastWriteTimeUtc,
                    Attributes = FileAttributes.Normal
                };
            }

            string baseName = Path.GetFileName(clean);

            // 2. Fast-fail negative probe cache for known Explorer shell probes
            if (ExplorerProbeNames.Contains(baseName))
            {
                return null;
            }

            // 3. Negative check against cached parent directory
            string parent = GetParentPath(clean);
            if (_directoryListingCache.TryGetValue(parent, out var parentListing) && !parentListing.IsExpired(CacheTtl))
            {
                bool contains;
                lock (parentListing)
                {
                    contains = parentListing.ChildNames.Contains(baseName);
                }
                if (!contains)
                {
                    return null;
                }
            }

            // 4. Remote storage lookup
            try
            {
                var meta = _storage.GetMetadataAsync(clean).GetAwaiter().GetResult();
                if (meta != null)
                {
                    _metadataCache[clean] = new CachedMetadata(meta);
                }
                return meta;
            }
            catch
            {
                return null;
            }
        }

        public override int Init(object host)
        {
            if (host is FileSystemHost hostObj)
            {
                hostObj.SectorSize = 4096;
                hostObj.SectorsPerAllocationUnit = 1;
                hostObj.MaxComponentLength = 255;
                // Report filesystem as NTFS so Windows Explorer enables native drive capacity bar,
                // decorated free space display (System.PercentFull / System.Computer.DecoratedFreeSpace),
                // and standard Windows shell volume properties.
                hostObj.FileSystemName = "NTFS";
                hostObj.CaseSensitiveSearch = false;
                hostObj.CasePreservedNames = true;
                hostObj.UnicodeOnDisk = true;
                hostObj.VolumeCreationTime = (ulong)DateTime.UtcNow.ToFileTimeUtc();
                hostObj.VolumeSerialNumber = 0x4F50454E; // "OPEN"

                // High-performance WinFsp kernel caching (matching RaiDrive configuration)
                // Eliminates synchronous RPC trips from kernel to user mode on repeated metadata queries
                hostObj.FileInfoTimeout = 5000;      // 5s FileInfo cache in winfsp.sys kernel
                hostObj.DirInfoTimeout = 5000;       // 5s directory entry cache in winfsp.sys kernel
                hostObj.VolumeInfoTimeout = 30000;   // 30s volume information cache
                hostObj.SecurityTimeout = 30000;     // 30s security descriptor cache
            }
            return STATUS_SUCCESS;
        }

        public override int GetVolumeInfo(out VolumeInfo volumeInfo)
        {
            lock (_volumeInfoLock)
            {
                if (DateTime.UtcNow < _volumeInfoExpiryUtc && _cachedVolumeInfo.TotalSize > 0)
                {
                    volumeInfo = _cachedVolumeInfo;
                    return STATUS_SUCCESS;
                }
            }

            try
            {
                var vol = _storage.GetVolumeInfoAsync().GetAwaiter().GetResult();
                var vi = default(VolumeInfo);
                vi.TotalSize = vol.TotalSize;
                vi.FreeSize = vol.FreeSize;

                string label = vol.VolumeLabel ?? "Google Drive";
                if (label.Length > 31) label = label.Substring(0, 31);
                vi.SetVolumeLabel(label);

                lock (_volumeInfoLock)
                {
                    _cachedVolumeInfo = vi;
                    _volumeInfoExpiryUtc = DateTime.UtcNow.AddSeconds(30);
                }
                volumeInfo = vi;
                return STATUS_SUCCESS;
            }
            catch
            {
                var vi = default(VolumeInfo);
                vi.TotalSize = 100UL * 1024 * 1024 * 1024;
                vi.FreeSize = 50UL * 1024 * 1024 * 1024;
                vi.SetVolumeLabel("OpenMount");
                volumeInfo = vi;
                return STATUS_SUCCESS;
            }
        }

        public override int SetVolumeLabel(string volumeLabel, out VolumeInfo volumeInfo)
        {
            lock (_volumeInfoLock)
            {
                if (!string.IsNullOrEmpty(volumeLabel))
                {
                    string safeLabel = volumeLabel.Length > 31 ? volumeLabel.Substring(0, 31) : volumeLabel;
                    _cachedVolumeInfo.SetVolumeLabel(safeLabel);
                }
            }
            return GetVolumeInfo(out volumeInfo);
        }

        public override int GetSecurityByName(string fileName, out uint fileAttributes, ref byte[] securityDescriptor)
        {
            fileAttributes = 0;
            if (string.IsNullOrEmpty(fileName) || fileName == "\\" || fileName == "/")
            {
                fileAttributes = (uint)FileAttributes.Directory;
                securityDescriptor = DefaultSecurityDescriptor;
                return STATUS_SUCCESS;
            }

            string clean = NormalizePath(fileName);
            if (_activeNodes.TryGetValue(clean, out var activeNode))
            {
                fileAttributes = (uint)activeNode.Attributes;
                if (activeNode.IsDirectory)
                {
                    fileAttributes |= (uint)FileAttributes.Directory;
                }
                securityDescriptor = DefaultSecurityDescriptor;
                return STATUS_SUCCESS;
            }

            var meta = GetCachedOrRemoteMetadata(clean);
            if (meta == null)
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }

            fileAttributes = (uint)meta.Attributes;
            if (meta.IsDirectory)
            {
                fileAttributes |= (uint)FileAttributes.Directory;
            }
            securityDescriptor = DefaultSecurityDescriptor;
            return STATUS_SUCCESS;
        }

        public override int Create(
            string fileName,
            uint createOptions,
            uint grantedAccess,
            uint fileAttributes,
            byte[] securityDescriptor,
            ulong allocationSize,
            out object fileNode,
            out object fileDesc,
            out FileInfo fileInfo,
            out string normalizedName)
        {
            fileNode = null!;
            fileDesc = null!;
            fileInfo = default;
            normalizedName = null!;

            if (_config.MonitorProcessAccess)
            {
                int pid = SafeGetOperationProcessId();
                if (pid > 0)
                {
                    _processMonitor.RecordAccess(pid, fileName, (createOptions & FILE_DIRECTORY_FILE) != 0 ? "CreateDirectory" : "CreateFile");
                }
            }

            bool isDir = (createOptions & FILE_DIRECTORY_FILE) != 0;
            if (isDir)
            {
                try
                {
                    _storage.CreateDirectoryAsync(fileName).GetAwaiter().GetResult();
                    InvalidateCache(fileName);
                    var node = AcquireNode(fileName, true, 0, (FileAttributes)fileAttributes);
                    var desc = new VirtualFileDesc(node, grantedAccess);
                    fileNode = node;
                    fileDesc = desc;
                    fileInfo = CreateFileInfo(node);
                    return STATUS_SUCCESS;
                }
                catch
                {
                    return STATUS_ACCESS_DENIED;
                }
            }
            else
            {
                try
                {
                    InvalidateCache(fileName);
                    string localPath = _cacheManager.PrepareStagingFileAsync(fileName, 0, DateTimeOffset.UtcNow, null).GetAwaiter().GetResult();
                    var node = AcquireNode(fileName, false, 0, (FileAttributes)fileAttributes);
                    node.ActiveStagingFilePath = localPath;
                    var desc = new VirtualFileDesc(node, grantedAccess)
                    {
                        LocalFilePath = localPath,
                        LocalFileStream = new FileStream(localPath, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, StagingBufferSize),
                        IsModified = true
                    };

                    fileNode = node;
                    fileDesc = desc;
                    fileInfo = CreateFileInfo(node);
                    return STATUS_SUCCESS;
                }
                catch
                {
                    return STATUS_ACCESS_DENIED;
                }
            }
        }

        public override int Open(
            string fileName,
            uint createOptions,
            uint grantedAccess,
            out object fileNode,
            out object fileDesc,
            out FileInfo fileInfo,
            out string normalizedName)
        {
            fileNode = null!;
            fileDesc = null!;
            fileInfo = default;
            normalizedName = null!;

            if (_config.MonitorProcessAccess)
            {
                int pid = SafeGetOperationProcessId();
                if (pid > 0)
                {
                    _processMonitor.RecordAccess(pid, fileName, "Open");
                }
            }

            if (string.IsNullOrEmpty(fileName) || fileName == "\\" || fileName == "/")
            {
                var rootNode = AcquireNode("\\", true);
                var rootDesc = new VirtualFileDesc(rootNode, grantedAccess);
                fileNode = rootNode;
                fileDesc = rootDesc;
                fileInfo = CreateFileInfo(rootNode);
                return STATUS_SUCCESS;
            }

            string clean = NormalizePath(fileName);
            if (_activeNodes.TryGetValue(clean, out var existingNode))
            {
                var node = AcquireNode(fileName, existingNode.IsDirectory, existingNode.Size, existingNode.Attributes);
                var desc = new VirtualFileDesc(node, grantedAccess);

                fileNode = node;
                fileDesc = desc;
                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }

            try
            {
                var meta = GetCachedOrRemoteMetadata(clean);
                if (meta == null)
                {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                }

                if (meta.IsDirectory)
                {
                    var node = AcquireNode(fileName, true, 0, meta.Attributes);
                    node.CreationTime = meta.CreatedTime;
                    node.LastAccessTime = meta.LastAccessTime;
                    node.LastWriteTime = meta.LastModifiedTime;

                    var desc = new VirtualFileDesc(node, grantedAccess);
                    fileNode = node;
                    fileDesc = desc;
                    fileInfo = CreateFileInfo(node);
                    return STATUS_SUCCESS;
                }
                else
                {
                    // Lazy Open: do not block or download in Open
                    var node = AcquireNode(fileName, false, meta.Size, meta.Attributes);
                    node.CreationTime = meta.CreatedTime;
                    node.LastAccessTime = meta.LastAccessTime;
                    node.LastWriteTime = meta.LastModifiedTime;

                    var desc = new VirtualFileDesc(node, grantedAccess);
                    fileNode = node;
                    fileDesc = desc;
                    fileInfo = CreateFileInfo(node);
                    return STATUS_SUCCESS;
                }
            }
            catch
            {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
        }

        public override int Overwrite(
            object fileNode,
            object fileDesc,
            uint fileAttributes,
            bool replaceFileAttributes,
            ulong allocationSize,
            out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            lock (node.LockObj)
            {
                desc.ReleaseRangeBuffer();
                if (desc.LocalFileStream == null)
                {
                    string localPath = _cacheManager.PrepareStagingFileAsync(node.Path, 0, DateTimeOffset.UtcNow, null).GetAwaiter().GetResult();
                    desc.LocalFilePath = localPath;
                    node.ActiveStagingFilePath = localPath;
                    desc.LocalFileStream = new FileStream(localPath, FileMode.Create, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, StagingBufferSize);
                }

                desc.LocalFileStream.SetLength(0);
                node.Size = 0;
                desc.IsModified = true;

                if (replaceFileAttributes)
                    node.Attributes = (FileAttributes)fileAttributes;
                else
                    node.Attributes |= (FileAttributes)fileAttributes;

                node.LastWriteTime = DateTimeOffset.UtcNow;
                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }
        }

        public override int Read(
            object fileNode,
            object fileDesc,
            IntPtr buffer,
            ulong offset,
            uint length,
            out uint bytesTransferred)
        {
            bytesTransferred = 0;
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            bool needPid = (_config.MonitorProcessAccess && !desc.HasRecordedRead) ||
                           !_config.EnableFilePreview ||
                           (desc.LocalFileStream == null && _config.EnableFilePreview);
            int callingPid = needPid ? SafeGetOperationProcessId() : 0;

            if (_config.MonitorProcessAccess && !desc.HasRecordedRead && callingPid > 0)
            {
                desc.HasRecordedRead = true;
                _processMonitor.RecordAccess(callingPid, node.Path, "Read");
            }

            if (!_config.EnableFilePreview && callingPid > 0 && _processMonitor.IsPreviewProcess(callingPid))
            {
                return STATUS_NOT_SUPPORTED;
            }

            long nodeSize;
            DateTimeOffset nodeLastWrite;

            lock (node.LockObj)
            {
                nodeSize = node.Size;
                nodeLastWrite = node.LastWriteTime;

                if (offset >= (ulong)nodeSize)
                {
                    return STATUS_END_OF_FILE;
                }

                uint toReadLocked = (uint)Math.Min((ulong)length, (ulong)nodeSize - offset);
                if (toReadLocked == 0)
                {
                    return STATUS_SUCCESS;
                }

                // 1. If file descriptor already has an active local stream:
                if (desc.LocalFileStream != null)
                {
                    desc.LocalFileStream.Seek((long)offset, SeekOrigin.Begin);
                    bytesTransferred = ReadStreamToIntPtr(desc.LocalFileStream, buffer, toReadLocked);
                    return STATUS_SUCCESS;
                }

                // 2. Attach existing local file (in-flight upload, active concurrent staging file, or already cached file of ANY size including 1 GB+)
                string? existingLocalPath = null;
                if (_asyncUploadQueue != null && _asyncUploadQueue.TryGetInFlightLocalPath(node.Path, out var inFlightPath))
                {
                    existingLocalPath = inFlightPath;
                }
                else if (!string.IsNullOrEmpty(node.ActiveStagingFilePath) && File.Exists(node.ActiveStagingFilePath))
                {
                    existingLocalPath = node.ActiveStagingFilePath;
                }
                else if (_cacheManager.TryGetCachedOrStagedFilePath(node.Path, nodeSize, out var cachedPath))
                {
                    existingLocalPath = cachedPath;
                }

                if (!string.IsNullOrEmpty(existingLocalPath) && File.Exists(existingLocalPath))
                {
                    try
                    {
                        desc.LocalFilePath = existingLocalPath;
                        desc.LocalFileStream = new FileStream(
                            existingLocalPath,
                            FileMode.Open,
                            FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete,
                            StagingBufferSize);
                        desc.LocalFileStream.Seek((long)offset, SeekOrigin.Begin);
                        bytesTransferred = ReadStreamToIntPtr(desc.LocalFileStream, buffer, toReadLocked);
                        return STATUS_SUCCESS;
                    }
                    catch { }
                }

                // 3. Check in-memory read-ahead range buffer for large remote files
                if (desc.RangeChunkBuffer != null &&
                    (long)offset >= desc.RangeChunkOffset &&
                    (long)offset + toReadLocked <= desc.RangeChunkOffset + desc.RangeChunkLength)
                {
                    int srcOffset = (int)((long)offset - desc.RangeChunkOffset);
                    Marshal.Copy(desc.RangeChunkBuffer, srcOffset, buffer, (int)toReadLocked);
                    bytesTransferred = toReadLocked;
                    return STATUS_SUCCESS;
                }
            }

            uint toRead = (uint)Math.Min((ulong)length, (ulong)nodeSize - offset);

            // Fast Preview: if file preview is enabled and request comes from a preview process (prevhost / thumbnailhost)
            if (_config.EnableFilePreview && callingPid > 0 && _processMonitor.IsPreviewProcess(callingPid))
            {
                try
                {
                    using var previewStream = _storage.OpenReadAsync(node.Path, (long)offset, (long)toRead).GetAwaiter().GetResult();
                    bytesTransferred = ReadStreamToIntPtr(previewStream, buffer, toRead);
                    return STATUS_SUCCESS;
                }
                catch
                {
                    // Fallback to caching
                }
            }

            // 4. Normal files (<= 64 MB): Ensure cached locally outside node.LockObj to avoid blocking concurrent operations
            if (nodeSize <= FileCacheManager.FullCacheSizeThreshold)
            {
                try
                {
                    string localPath = _cacheManager.EnsureFileCachedAsync(
                        node.Path,
                        nodeSize,
                        nodeLastWrite,
                        (off, len, ct) => _storage.OpenReadAsync(node.Path, off, len, ct)).GetAwaiter().GetResult();

                    lock (node.LockObj)
                    {
                        if (desc.LocalFileStream == null)
                        {
                            desc.LocalFilePath = localPath;
                            desc.LocalFileStream = new FileStream(
                                localPath,
                                FileMode.Open,
                                FileAccess.ReadWrite,
                                FileShare.ReadWrite | FileShare.Delete,
                                StagingBufferSize);
                        }

                        desc.LocalFileStream.Seek((long)offset, SeekOrigin.Begin);
                        bytesTransferred = ReadStreamToIntPtr(desc.LocalFileStream, buffer, toRead);
                        return STATUS_SUCCESS;
                    }
                }
                catch
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
            else
            {
                // 5. Large remote files (> 64 MB): Use 4 MB read-ahead chunking to avoid 64 KB HTTP Range storms
                try
                {
                    if (toRead <= RangeReadAheadBytes)
                    {
                        long fetchLen = Math.Min((long)RangeReadAheadBytes, nodeSize - (long)offset);
                        byte[] rented = ArrayPool<byte>.Shared.Rent((int)fetchLen);
                        int totalFetched = 0;
                        try
                        {
                            using (var rangeStream = _storage.OpenReadAsync(node.Path, (long)offset, fetchLen).GetAwaiter().GetResult())
                            {
                                while (totalFetched < (int)fetchLen)
                                {
                                    int r = rangeStream.Read(rented, totalFetched, (int)fetchLen - totalFetched);
                                    if (r <= 0) break;
                                    totalFetched += r;
                                }
                            }

                            int copyLen = Math.Min((int)toRead, totalFetched);
                            if (copyLen > 0)
                            {
                                Marshal.Copy(rented, 0, buffer, copyLen);
                            }
                            bytesTransferred = (uint)copyLen;

                            lock (node.LockObj)
                            {
                                desc.ReleaseRangeBuffer();
                                desc.RangeChunkBuffer = rented;
                                desc.RangeChunkOffset = (long)offset;
                                desc.RangeChunkLength = totalFetched;
                                rented = null!;
                            }
                            return STATUS_SUCCESS;
                        }
                        finally
                        {
                            if (rented != null)
                            {
                                ArrayPool<byte>.Shared.Return(rented);
                            }
                        }
                    }
                    else
                    {
                        using var rangeStream = _storage.OpenReadAsync(node.Path, (long)offset, (long)toRead).GetAwaiter().GetResult();
                        bytesTransferred = ReadStreamToIntPtr(rangeStream, buffer, toRead);
                        return STATUS_SUCCESS;
                    }
                }
                catch
                {
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }

        public override int Write(
            object fileNode,
            object fileDesc,
            IntPtr buffer,
            ulong offset,
            uint length,
            bool writeToEndOfFile,
            bool constrainedIo,
            out uint bytesTransferred,
            out FileInfo fileInfo)
        {
            bytesTransferred = 0;
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            if (_config.MonitorProcessAccess && !desc.HasRecordedWrite)
            {
                int pid = SafeGetOperationProcessId();
                if (pid > 0)
                {
                    desc.HasRecordedWrite = true;
                    _processMonitor.RecordAccess(pid, node.Path, "Write");
                }
            }

            lock (node.LockObj)
            {
                desc.ReleaseRangeBuffer();

                if (desc.LocalFileStream == null || !desc.LocalFileStream.CanWrite)
                {
                    try
                    {
                        desc.LocalFileStream?.Dispose();
                        desc.LocalFileStream = null;

                        string localPath = _cacheManager.PrepareStagingFileAsync(
                            node.Path,
                            node.Size,
                            node.LastWriteTime,
                            node.Size > 0 ? ((off, len, ct) => _storage.OpenReadAsync(node.Path, off, len, ct)) : null).GetAwaiter().GetResult();
                        desc.LocalFilePath = localPath;
                        node.ActiveStagingFilePath = localPath;
                        desc.LocalFileStream = new FileStream(
                            localPath,
                            FileMode.OpenOrCreate,
                            FileAccess.ReadWrite,
                            FileShare.ReadWrite | FileShare.Delete,
                            StagingBufferSize);
                    }
                    catch
                    {
                        fileInfo = CreateFileInfo(node);
                        return STATUS_ACCESS_DENIED;
                    }
                }

                long writePos = writeToEndOfFile ? desc.LocalFileStream.Length : (long)offset;
                desc.LocalFileStream.Seek(writePos, SeekOrigin.Begin);

                uint written = WriteStreamFromIntPtr(desc.LocalFileStream, buffer, length);

                desc.IsModified = true;
                if (desc.LocalFileStream.Length > node.Size)
                {
                    node.Size = desc.LocalFileStream.Length;
                }
                node.LastWriteTime = DateTimeOffset.UtcNow;

                bytesTransferred = written;
                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }
        }

        public override int SetFileSize(
            object fileNode,
            object fileDesc,
            ulong newSize,
            bool setAllocationSize,
            out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            lock (node.LockObj)
            {
                if (!setAllocationSize)
                {
                    desc.ReleaseRangeBuffer();

                    if (desc.LocalFileStream == null || !desc.LocalFileStream.CanWrite)
                    {
                        try
                        {
                            desc.LocalFileStream?.Dispose();
                            desc.LocalFileStream = null;

                            string localPath = _cacheManager.PrepareStagingFileAsync(
                                node.Path,
                                node.Size,
                                node.LastWriteTime,
                                node.Size > 0 ? ((off, len, ct) => _storage.OpenReadAsync(node.Path, off, len, ct)) : null).GetAwaiter().GetResult();
                            desc.LocalFilePath = localPath;
                            node.ActiveStagingFilePath = localPath;
                            desc.LocalFileStream = new FileStream(
                                localPath,
                                FileMode.OpenOrCreate,
                                FileAccess.ReadWrite,
                                FileShare.ReadWrite | FileShare.Delete,
                                StagingBufferSize);
                        }
                        catch
                        {
                            fileInfo = CreateFileInfo(node);
                            return STATUS_ACCESS_DENIED;
                        }
                    }

                    desc.LocalFileStream.SetLength((long)newSize);
                    node.Size = (long)newSize;
                    desc.IsModified = true;
                    node.LastWriteTime = DateTimeOffset.UtcNow;
                }

                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }
        }

        public override int SetBasicInfo(
            object fileNode,
            object fileDesc,
            uint fileAttributes,
            ulong creationTime,
            ulong lastAccessTime,
            ulong lastWriteTime,
            ulong changeTime,
            out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = fileDesc as VirtualFileDesc;

            lock (node.LockObj)
            {
                if (fileAttributes != 0 && fileAttributes != uint.MaxValue)
                {
                    node.Attributes = (FileAttributes)fileAttributes;
                }
                if (creationTime != 0)
                {
                    node.CreationTime = DateTimeOffset.FromFileTime((long)creationTime);
                }
                if (lastAccessTime != 0)
                {
                    node.LastAccessTime = DateTimeOffset.FromFileTime((long)lastAccessTime);
                }
                if (lastWriteTime != 0)
                {
                    node.LastWriteTime = DateTimeOffset.FromFileTime((long)lastWriteTime);

                    bool isStagedOrInFlight = (desc != null && desc.IsModified) ||
                                              !string.IsNullOrEmpty(node.ActiveStagingFilePath) ||
                                              (_asyncUploadQueue != null && _asyncUploadQueue.TryGetInFlightLocalPath(node.Path, out _));

                    if (_config.MaintainDateModified && !isStagedOrInFlight)
                    {
                        var mtime = node.LastWriteTime;
                        var p = node.Path;
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await _storage.SetLastModifiedTimeAsync(p, mtime).ConfigureAwait(false);
                            }
                            catch { }
                        });
                    }
                }

                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }
        }

        public override int GetFileInfo(object fileNode, object fileDesc, out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;
            fileInfo = CreateFileInfo(node);
            return STATUS_SUCCESS;
        }

        public override int CanDelete(object fileNode, object fileDesc, string fileName)
        {
            var node = (VirtualFileNode)fileNode;
            if (node.IsDirectory)
            {
                try
                {
                    var items = _storage.ListDirectoryAsync(node.Path).GetAwaiter().GetResult();
                    if (items != null && items.Count > 0)
                    {
                        return STATUS_DIRECTORY_NOT_EMPTY;
                    }
                }
                catch { }
            }
            return STATUS_SUCCESS;
        }

        public override int SetDelete(object fileNode, object fileDesc, string fileName, bool deleteFile)
        {
            var node = (VirtualFileNode)fileNode;
            node.DeleteOnClose = deleteFile;
            return STATUS_SUCCESS;
        }

        public override int Rename(object fileNode, object fileDesc, string fileName, string newFileName, bool replaceIfExists)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            if (_config.MonitorProcessAccess)
            {
                int pid = SafeGetOperationProcessId();
                if (pid > 0)
                {
                    _processMonitor.RecordAccess(pid, fileName, "Move/Rename");
                }
            }

            try
            {
                // If modified in staging, flush before remote move
                if (desc.IsModified && desc.LocalFileStream != null)
                {
                    desc.LocalFileStream.Flush();
                    desc.LocalFileStream.Position = 0;
                    _storage.CreateFileAsync(fileName, desc.LocalFileStream).GetAwaiter().GetResult();
                    desc.IsModified = false;
                }

                _storage.MoveAsync(fileName, newFileName).GetAwaiter().GetResult();
                InvalidateCache(fileName);
                InvalidateCache(newFileName);
                _cacheManager.Invalidate(fileName);
                _cacheManager.Invalidate(newFileName);

                string oldNorm = NormalizePath(fileName);
                string newNorm = NormalizePath(newFileName);
                if (_activeNodes.TryRemove(oldNorm, out var n))
                {
                    n.Path = newNorm;
                    _activeNodes[newNorm] = n;
                }
                else
                {
                    node.Path = newNorm;
                }
                return STATUS_SUCCESS;
            }
            catch
            {
                return STATUS_ACCESS_DENIED;
            }
        }

        public override void Cleanup(object fileNode, object fileDesc, string fileName, uint flags)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            if (_config.MonitorProcessAccess)
            {
                int pid = SafeGetOperationProcessId();
                if (pid > 0)
                {
                    _processMonitor.RecordAccess(pid, node.Path, "Cleanup");
                }
            }

            if ((flags & 0x01) != 0 || node.DeleteOnClose)
            {
                try
                {
                    if (node.IsDirectory)
                    {
                        _storage.DeleteDirectoryAsync(node.Path, false).GetAwaiter().GetResult();
                    }
                    else
                    {
                        _storage.DeleteFileAsync(node.Path).GetAwaiter().GetResult();
                    }
                    InvalidateCache(node.Path);
                    _cacheManager.Invalidate(node.Path);
                }
                catch { }

                _activeNodes.TryRemove(NormalizePath(node.Path), out _);
                desc.Dispose();
                return;
            }

            if (desc.IsModified && desc.LocalFileStream != null)
            {
                try
                {
                    desc.LocalFileStream.Flush();
                    node.Size = desc.LocalFileStream.Length;

                    if (_config.AsyncUpload && _asyncUploadQueue != null && !string.IsNullOrEmpty(desc.LocalFilePath))
                    {
                        string stagedPath = desc.LocalFilePath;
                        desc.LocalFileStream.Dispose();
                        desc.LocalFileStream = null;
                        desc.IsModified = false;

                        _asyncUploadQueue.Enqueue(node.Path, stagedPath);
                        UpdateCacheForUploadedFile(node);
                    }
                    else
                    {
                        if (!string.IsNullOrEmpty(desc.LocalFilePath) && File.Exists(desc.LocalFilePath))
                        {
                            string stagedPath = desc.LocalFilePath;
                            desc.LocalFileStream.Dispose();
                            desc.LocalFileStream = null;

                            using (var uploadStream = new FileStream(
                                stagedPath,
                                FileMode.Open,
                                FileAccess.Read,
                                FileShare.ReadWrite | FileShare.Delete,
                                StagingBufferSize,
                                FileOptions.SequentialScan | FileOptions.Asynchronous))
                            {
                                _storage.CreateFileAsync(node.Path, uploadStream).GetAwaiter().GetResult();
                            }

                            desc.IsModified = false;
                            _cacheManager.MarkUploadCompleted(node.Path, node.Size, node.LastWriteTime);
                        }
                        else
                        {
                            desc.LocalFileStream.Position = 0;
                            _storage.CreateFileAsync(node.Path, desc.LocalFileStream).GetAwaiter().GetResult();
                            desc.IsModified = false;
                        }

                        UpdateCacheForUploadedFile(node);
                    }
                }
                catch
                {
                    desc.PreserveUnsavedChanges();
                }
            }
        }

        public override void Close(object fileNode, object fileDesc)
        {
            var desc = (VirtualFileDesc)fileDesc;
            var node = (VirtualFileNode)fileNode;
            desc.Dispose();
            ReleaseNode(node);
        }

        public override int Flush(object fileNode, object fileDesc, out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;
            var desc = (VirtualFileDesc)fileDesc;

            lock (node.LockObj)
            {
                if (desc.IsModified && desc.LocalFileStream != null)
                {
                    desc.LocalFileStream.Flush();
                }
                fileInfo = CreateFileInfo(node);
                return STATUS_SUCCESS;
            }
        }

        public override int GetSecurity(object fileNode, object fileDesc, ref byte[] securityDescriptor)
        {
            securityDescriptor = DefaultSecurityDescriptor;
            return STATUS_SUCCESS;
        }

        public override int SetSecurity(object fileNode, object fileDesc, AccessControlSections sections, byte[] securityDescriptor)
        {
            return STATUS_SUCCESS;
        }

        public override bool ReadDirectoryEntry(
            object fileNode,
            object fileDesc,
            string pattern,
            string marker,
            ref object context,
            out string fileName,
            out FileInfo fileInfo)
        {
            var node = (VirtualFileNode)fileNode;

            if (context == null)
            {
                var list = new List<DirEntryItem>();
                list.Add(new DirEntryItem(".", true, 0, node.CreationTime, node.LastAccessTime, node.LastWriteTime, FileAttributes.Directory));
                list.Add(new DirEntryItem("..", true, 0, node.CreationTime, node.LastAccessTime, node.LastWriteTime, FileAttributes.Directory));

                try
                {
                    var items = _storage.ListDirectoryAsync(node.Path).GetAwaiter().GetResult();
                    if (items != null)
                    {
                        var childNames = new List<string>(items.Count);
                        foreach (var it in items)
                        {
                            string childPath = NormalizePath(node.Path == "\\" ? "\\" + it.Name : node.Path + "\\" + it.Name);
                            _metadataCache[childPath] = new CachedMetadata(it);
                            childNames.Add(it.Name);

                            list.Add(new DirEntryItem(
                                it.Name,
                                it.IsDirectory,
                                it.Size,
                                it.CreatedTime,
                                it.LastAccessTime,
                                it.LastModifiedTime,
                                it.Attributes));
                        }
                        _directoryListingCache[NormalizePath(node.Path)] = new CachedDirectoryListing(childNames);
                        _folderPropertiesCache.Update(NormalizePath(node.Path), items);
                    }
                }
                catch { }

                int startIndex = 0;
                if (!string.IsNullOrEmpty(marker))
                {
                    int idx = list.FindIndex(x => string.Equals(x.Name, marker, StringComparison.OrdinalIgnoreCase));
                    if (idx >= 0) startIndex = idx + 1;
                }

                context = new DirEnumContext(list, startIndex);
            }

            var ctx = (DirEnumContext)context;
            if (ctx.CurrentIndex < ctx.Items.Count)
            {
                var cur = ctx.Items[ctx.CurrentIndex++];
                fileName = cur.Name;
                fileInfo = cur.ToFileInfo();
                return true;
            }

            fileName = null!;
            fileInfo = default;
            return false;
        }

        private static FileInfo CreateFileInfo(VirtualFileNode node)
        {
            return new FileInfo
            {
                FileAttributes = (uint)node.Attributes,
                ReparseTag = 0,
                AllocationSize = node.AllocationSize,
                FileSize = (ulong)Math.Max(0, node.Size),
                CreationTime = (ulong)node.CreationTime.ToFileTime(),
                LastAccessTime = (ulong)node.LastAccessTime.ToFileTime(),
                LastWriteTime = (ulong)node.LastWriteTime.ToFileTime(),
                ChangeTime = (ulong)node.LastWriteTime.ToFileTime(),
                IndexNumber = 0,
                HardLinks = 1
            };
        }

        private class DirEnumContext
        {
            public List<DirEntryItem> Items { get; }
            public int CurrentIndex { get; set; }

            public DirEnumContext(List<DirEntryItem> items, int startIndex)
            {
                Items = items;
                CurrentIndex = startIndex;
            }
        }

        private class DirEntryItem
        {
            public string Name { get; }
            public bool IsDirectory { get; }
            public long Size { get; }
            public DateTimeOffset CreationTime { get; }
            public DateTimeOffset LastAccessTime { get; }
            public DateTimeOffset LastWriteTime { get; }
            public FileAttributes Attributes { get; }

            public DirEntryItem(
                string name,
                bool isDirectory,
                long size,
                DateTimeOffset creationTime,
                DateTimeOffset lastAccessTime,
                DateTimeOffset lastWriteTime,
                FileAttributes attributes = FileAttributes.Normal)
            {
                Name = name;
                IsDirectory = isDirectory;
                Size = size;
                CreationTime = creationTime;
                LastAccessTime = lastAccessTime;
                LastWriteTime = lastWriteTime;
                Attributes = isDirectory ? (attributes | FileAttributes.Directory) : attributes;
            }

            public FileInfo ToFileInfo()
            {
                return new FileInfo
                {
                    FileAttributes = (uint)Attributes,
                    ReparseTag = 0,
                    AllocationSize = IsDirectory ? 0 : (ulong)((Size + 4095) / 4096 * 4096),
                    FileSize = (ulong)Math.Max(0, Size),
                    CreationTime = (ulong)CreationTime.ToFileTime(),
                    LastAccessTime = (ulong)LastAccessTime.ToFileTime(),
                    LastWriteTime = (ulong)LastWriteTime.ToFileTime(),
                    ChangeTime = (ulong)LastWriteTime.ToFileTime(),
                    IndexNumber = 0,
                    HardLinks = 1
                };
            }
        }
    }
}
