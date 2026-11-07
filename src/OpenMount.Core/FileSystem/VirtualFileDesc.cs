using System;
using System.Buffers;
using System.IO;

namespace OpenMount.Core.FileSystem
{
    public class VirtualFileDesc : IDisposable
    {
        public VirtualFileNode Node { get; }
        public FileStream? LocalFileStream { get; set; }
        public string? LocalFilePath { get; set; }
        public string? StagingFilePath
        {
            get => LocalFilePath;
            set => LocalFilePath = value;
        }
        public bool IsModified { get; set; }
        public uint GrantedAccess { get; }
        public bool HasRecordedRead { get; set; }
        public bool HasRecordedWrite { get; set; }

        // Read-ahead range chunk cache for large remote files (> 64 MB) to avoid per-64KB HTTP requests
        public byte[]? RangeChunkBuffer { get; set; }
        public long RangeChunkOffset { get; set; } = -1;
        public int RangeChunkLength { get; set; }

        public static string UnsavedRecoveryDir { get; set; } =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenMount", "unsaved");

        public string? LastPreservedRecoveryPath { get; private set; }

        public VirtualFileDesc(VirtualFileNode node, uint grantedAccess = 0)
        {
            Node = node ?? throw new ArgumentNullException(nameof(node));
            GrantedAccess = grantedAccess;
        }

        public Stream GetActiveStream()
        {
            if (LocalFileStream != null) return LocalFileStream;
            throw new InvalidOperationException("No active stream on file descriptor.");
        }

        public void ReleaseRangeBuffer()
        {
            var buf = RangeChunkBuffer;
            if (buf != null)
            {
                RangeChunkBuffer = null;
                RangeChunkOffset = -1;
                RangeChunkLength = 0;
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        public void PreserveUnsavedChanges()
        {
            if (!IsModified || string.IsNullOrEmpty(LocalFilePath) || !File.Exists(LocalFilePath))
                return;

            try
            {
                if (!Directory.Exists(UnsavedRecoveryDir))
                {
                    Directory.CreateDirectory(UnsavedRecoveryDir);
                }
                string safeName = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Path.GetFileName(LocalFilePath)}_{Path.GetFileName(Node.Path)}";
                string recoveryPath = Path.Combine(UnsavedRecoveryDir, safeName);
                File.Copy(LocalFilePath, recoveryPath, overwrite: true);
                LastPreservedRecoveryPath = recoveryPath;
            }
            catch { }
        }

        public void Dispose()
        {
            ReleaseRangeBuffer();

            try
            {
                LocalFileStream?.Dispose();
                LocalFileStream = null;
            }
            catch { }

            if (IsModified && !string.IsNullOrEmpty(LocalFilePath) && File.Exists(LocalFilePath))
            {
                PreserveUnsavedChanges();
                try
                {
                    File.Delete(LocalFilePath);
                }
                catch { }
            }
        }
    }
}
