using Microsoft.Extensions.Logging;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Rebuilds target PE with captured IL.")]
    internal static class JitTargetRebuilder
    {
        private const uint SectionContainsCode = 0x00000020;
        private const uint SectionMemoryExecute = 0x20000000;
        private const uint SectionMemoryRead = 0x40000000;
        private const uint CorFlagStrongNameSigned = 0x00000008;

        [HelperClass.SomeElementsInfos("Writes captured method bodies into output PE.")]
        public static void Rebuild(string sourcePath, string outputPath, IEnumerable<JitMethodSnapshot> snapshots)
        {
            if (string.IsNullOrWhiteSpace(sourcePath))
                throw new ArgumentException("Source path is required.", nameof(sourcePath));
            if (string.IsNullOrWhiteSpace(outputPath))
                throw new ArgumentException("Output path is required.", nameof(outputPath));
            ArgumentNullException.ThrowIfNull(snapshots);

            JitMethodSnapshot[] methods = snapshots
                .Where(static method => method.ILCode.Length > 0 && (method.MetadataToken & unchecked((int)0xFF000000)) == 0x06000000)
                .OrderBy(static method => method.RowId)
                .ToArray();

            if (methods.Length == 0)
                throw new InvalidOperationException("No JIT-captured MethodDef bodies are available for rebuilding.");

            byte[] image = File.ReadAllBytes(sourcePath);
            using MemoryStream sourceStream = new(image, writable: false);
            using PEReader peReader = new(sourceStream, PEStreamOptions.LeaveOpen);
            _ = peReader.GetMetadataReader();

            BlobBuilder methodBodyBuilder = new();
            MethodBodyStreamEncoder bodyEncoder = new(methodBodyBuilder);
            Dictionary<int, int> bodyOffsets = new(methods.Length);
            int skippedEh = 0;

            foreach (ref readonly JitMethodSnapshot method in methods.AsSpan())
            {
                if (method.EHCount != (uint)method.ExceptionRegions.Length)
                {
                    skippedEh++;
                    ThisStaticClass.Logger.LogWarning("[JIT-REBUILD] Skipping token 0x{Token:X8}: JIT EHCount={JitEhCount}, captured EH={CapturedEhCount}", method.MetadataToken, method.EHCount, method.ExceptionRegions.Length);
                    continue;
                }

                StandaloneSignatureHandle localSignature = GetLocalSignatureHandle(method.LocalSignatureToken);
                MethodBodyAttributes attributes = method.InitLocals ? MethodBodyAttributes.InitLocals : MethodBodyAttributes.None;
                MethodBodyStreamEncoder.MethodBody body = bodyEncoder.AddMethodBody(
                    method.ILCode.Length,
                    checked((int)Math.Min(method.MaxStack, ushort.MaxValue)),
                    method.ExceptionRegions.Length,
                    hasSmallExceptionRegions: false,
                    localSignature,
                    attributes);

                new BlobWriter(body.Instructions).WriteBytes(method.ILCode);
                EncodeExceptionRegions(body.ExceptionRegions, method.ExceptionRegions);
                bodyOffsets[method.MetadataToken] = body.Offset;
            }

            if (bodyOffsets.Count == 0)
                throw new InvalidOperationException("No captured method body could be safely encoded.");

            byte[] bodyStream = methodBodyBuilder.ToArray();
            PeLayoutInfo layout = PeLayoutInfo.Read(image);
            image = EnsureSectionHeaderRoom(image, layout);
            layout = PeLayoutInfo.Read(image);
            int sectionHeaderOffset = layout.SectionTableOffset + (layout.NumberOfSections * 40);

            int rawPointer = Align(Math.Max(image.Length, layout.LastSectionRawEnd), layout.FileAlignment);
            int rawSize = Align(bodyStream.Length, layout.FileAlignment);
            int virtualAddress = Align(layout.LastSectionVirtualEnd, layout.SectionAlignment);
            int virtualSize = bodyStream.Length;

            byte[] rebuilt = new byte[checked(rawPointer + rawSize)];
            image.AsSpan().CopyTo(rebuilt);
            bodyStream.AsSpan().CopyTo(rebuilt.AsSpan(rawPointer));

            WriteSectionHeader(rebuilt, sectionHeaderOffset, ".jitdmp", virtualSize, virtualAddress, rawSize, rawPointer);
            BinaryPrimitives.WriteUInt16LittleEndian(rebuilt.AsSpan(layout.PeHeaderOffset + 6, sizeof(ushort)), checked((ushort)(layout.NumberOfSections + 1)));
            int sizeOfCode = BinaryPrimitives.ReadInt32LittleEndian(rebuilt.AsSpan(layout.OptionalHeaderOffset + 4, sizeof(int)));
            BinaryPrimitives.WriteInt32LittleEndian(rebuilt.AsSpan(layout.OptionalHeaderOffset + 4, sizeof(int)), checked(sizeOfCode + rawSize));
            BinaryPrimitives.WriteInt32LittleEndian(rebuilt.AsSpan(layout.OptionalHeaderOffset + 56, sizeof(int)), Align(virtualAddress + virtualSize, layout.SectionAlignment));
            BinaryPrimitives.WriteUInt32LittleEndian(rebuilt.AsSpan(layout.OptionalHeaderOffset + 64, sizeof(uint)), 0);

            MetadataMethodRvaMap rvaMap = MetadataMethodRvaMap.Read(rebuilt, layout.MetadataFileOffset);
            foreach (KeyValuePair<int, int> body in bodyOffsets)
            {
                int newRva = checked(virtualAddress + body.Value);
                rvaMap.WriteMethodRva(rebuilt, body.Key, newRva);
            }

            StripInvalidAuthenticode(rebuilt, layout);
            StripInvalidStrongName(rebuilt, layout);

            string? directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllBytes(outputPath, rebuilt);
            ThisStaticClass.Logger.LogInformation("[JIT-REBUILD] Output={Output}; rebuilt={Rebuilt}; skippedEH={SkippedEh}; sectionRVA=0x{SectionRva:X8}", outputPath, bodyOffsets.Count, skippedEh, virtualAddress);
        }

        private static StandaloneSignatureHandle GetLocalSignatureHandle(int token)
        {
            if (token == 0)
                return default;

            if ((token & unchecked((int)0xFF000000)) != 0x11000000)
                throw new BadImageFormatException($"Invalid StandAloneSig token 0x{token:X8}.");

            return MetadataTokens.StandaloneSignatureHandle(token & 0x00FFFFFF);
        }

        private static void EncodeExceptionRegions(ExceptionRegionEncoder encoder, ImmutableArray<JitExceptionRegion> regions)
        {
            foreach (ref readonly JitExceptionRegion region in regions.AsSpan())
            {
                encoder = region.Kind switch
                {
                    JitExceptionRegionKind.Catch => encoder.AddCatch(region.TryOffset, region.TryLength, region.HandlerOffset, region.HandlerLength, MetadataTokens.EntityHandle(region.CatchTypeToken)),
                    JitExceptionRegionKind.Filter => encoder.AddFilter(region.TryOffset, region.TryLength, region.HandlerOffset, region.HandlerLength, region.FilterOffset),
                    JitExceptionRegionKind.Finally => encoder.AddFinally(region.TryOffset, region.TryLength, region.HandlerOffset, region.HandlerLength),
                    JitExceptionRegionKind.Fault => encoder.AddFault(region.TryOffset, region.TryLength, region.HandlerOffset, region.HandlerLength),
                    _ => throw new ArgumentOutOfRangeException(nameof(region.Kind))
                };
            }
        }


        private static byte[] EnsureSectionHeaderRoom(byte[] image, PeLayoutInfo layout)
        {
            int requiredHeaderEnd = checked(layout.SectionTableOffset + ((layout.NumberOfSections + 1) * 40));
            if (requiredHeaderEnd <= layout.FirstSectionRawPointer)
                return image;

            int newFirstRaw = Align(requiredHeaderEnd, layout.FileAlignment);
            int delta = checked(newFirstRaw - layout.FirstSectionRawPointer);
            if (delta <= 0)
                throw new BadImageFormatException("Unable to grow PE headers for the JIT dump section.");

            byte[] expanded = new byte[checked(image.Length + delta)];
            image.AsSpan(0, layout.FirstSectionRawPointer).CopyTo(expanded);
            image.AsSpan(layout.FirstSectionRawPointer).CopyTo(expanded.AsSpan(newFirstRaw));

            for (int i = 0; i < layout.NumberOfSections; i++)
            {
                int sectionHeader = layout.SectionTableOffset + (i * 40);
                int rawPointer = BinaryPrimitives.ReadInt32LittleEndian(expanded.AsSpan(sectionHeader + 20, 4));
                if (rawPointer != 0)
                    BinaryPrimitives.WriteInt32LittleEndian(expanded.AsSpan(sectionHeader + 20, 4), checked(rawPointer + delta));
            }

            int symbolTablePointer = BinaryPrimitives.ReadInt32LittleEndian(expanded.AsSpan(layout.PeHeaderOffset + 12, 4));
            if (symbolTablePointer != 0)
                BinaryPrimitives.WriteInt32LittleEndian(expanded.AsSpan(layout.PeHeaderOffset + 12, 4), checked(symbolTablePointer + delta));

            BinaryPrimitives.WriteInt32LittleEndian(expanded.AsSpan(layout.OptionalHeaderOffset + 60, 4), newFirstRaw);

            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(expanded.AsSpan(layout.OptionalHeaderOffset, 2));
            int dataDirectoryOffset = layout.OptionalHeaderOffset + (magic == 0x20B ? 112 : 96);
            int securityDirectoryOffset = dataDirectoryOffset + (4 * 8);
            int certificateFileOffset = BinaryPrimitives.ReadInt32LittleEndian(expanded.AsSpan(securityDirectoryOffset, 4));
            if (certificateFileOffset != 0)
                BinaryPrimitives.WriteInt32LittleEndian(expanded.AsSpan(securityDirectoryOffset, 4), checked(certificateFileOffset + delta));

            AdjustDebugDirectoryRawPointers(expanded, layout, dataDirectoryOffset, delta);

            ThisStaticClass.Logger.LogInformation("[JIT-REBUILD] Expanded PE headers by {Bytes} bytes to fit .jitdmp section header.", delta);
            return expanded;
        }


        private static void AdjustDebugDirectoryRawPointers(byte[] image, PeLayoutInfo layout, int dataDirectoryOffset, int delta)
        {
            const int DebugDirectoryIndex = 6;
            const int DebugDirectoryEntrySize = 28;
            const int PointerToRawDataOffset = 24;

            int directory = dataDirectoryOffset + (DebugDirectoryIndex * 8);
            int debugRva = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(directory, 4));
            int debugSize = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(directory + 4, 4));
            if (debugRva == 0 || debugSize < DebugDirectoryEntrySize || !layout.TryRvaToFileOffset(debugRva, out int oldDebugOffset))
                return;

            int debugOffset = checked(oldDebugOffset + delta);
            int count = debugSize / DebugDirectoryEntrySize;
            for (int i = 0; i < count; i++)
            {
                int entry = checked(debugOffset + (i * DebugDirectoryEntrySize));
                if (entry < 0 || entry > image.Length - DebugDirectoryEntrySize)
                    break;

                int pointer = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(entry + PointerToRawDataOffset, 4));
                if (pointer >= layout.FirstSectionRawPointer)
                    BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(entry + PointerToRawDataOffset, 4), checked(pointer + delta));
            }
        }

        private static void WriteSectionHeader(byte[] image, int offset, string name, int virtualSize, int virtualAddress, int rawSize, int rawPointer)
        {
            Span<byte> header = image.AsSpan(offset, 40);
            header.Clear();
            for (int i = 0; i < name.Length && i < 8; i++)
                header[i] = checked((byte)name[i]);

            BinaryPrimitives.WriteInt32LittleEndian(header.Slice(8, 4), virtualSize);
            BinaryPrimitives.WriteInt32LittleEndian(header.Slice(12, 4), virtualAddress);
            BinaryPrimitives.WriteInt32LittleEndian(header.Slice(16, 4), rawSize);
            BinaryPrimitives.WriteInt32LittleEndian(header.Slice(20, 4), rawPointer);
            BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(36, 4), SectionContainsCode | SectionMemoryExecute | SectionMemoryRead);
        }

        private static void StripInvalidAuthenticode(byte[] image, PeLayoutInfo layout)
        {





            ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(layout.OptionalHeaderOffset, 2));
            int dataDirectoryOffset = layout.OptionalHeaderOffset + (magic == 0x20B ? 112 : 96);
            int securityDirectoryOffset = dataDirectoryOffset + (4 * 8);
            Span<byte> securityDirectory = image.AsSpan(securityDirectoryOffset, 8);
            if (!securityDirectory.IsEmpty)
                securityDirectory.Clear();
        }

        private static void StripInvalidStrongName(byte[] image, PeLayoutInfo layout)
        {
            if (layout.CorHeaderFileOffset < 0)
                return;

            int flagsOffset = layout.CorHeaderFileOffset + 16;
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(flagsOffset, 4));
            if ((flags & CorFlagStrongNameSigned) == 0)
                return;

            flags &= ~CorFlagStrongNameSigned;
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(flagsOffset, 4), flags);

            int strongNameDirectoryOffset = layout.CorHeaderFileOffset + 32;
            int strongNameRva = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(strongNameDirectoryOffset, 4));
            int strongNameSize = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(strongNameDirectoryOffset + 4, 4));
            if (strongNameRva != 0 && strongNameSize > 0 && layout.TryRvaToFileOffset(strongNameRva, out int signatureOffset) && signatureOffset <= image.Length - strongNameSize)
                image.AsSpan(signatureOffset, strongNameSize).Clear();
        }

        private static int Align(int value, int alignment)
        {
            if (alignment <= 0)
                throw new ArgumentOutOfRangeException(nameof(alignment));
            return checked((value + alignment - 1) / alignment * alignment);
        }

        private sealed class PeLayoutInfo(
            int peHeaderOffset,
            int optionalHeaderOffset,
            int sectionTableOffset,
            int numberOfSections,
            int fileAlignment,
            int sectionAlignment,
            int firstSectionRawPointer,
            int lastSectionRawEnd,
            int lastSectionVirtualEnd,
            int metadataFileOffset,
            int corHeaderFileOffset,
            ImmutableArray<PeSection> sections)
        {
            public int PeHeaderOffset { get; } = peHeaderOffset;
            public int OptionalHeaderOffset { get; } = optionalHeaderOffset;
            public int SectionTableOffset { get; } = sectionTableOffset;
            public int NumberOfSections { get; } = numberOfSections;
            public int FileAlignment { get; } = fileAlignment;
            public int SectionAlignment { get; } = sectionAlignment;
            public int FirstSectionRawPointer { get; } = firstSectionRawPointer;
            public int LastSectionRawEnd { get; } = lastSectionRawEnd;
            public int LastSectionVirtualEnd { get; } = lastSectionVirtualEnd;
            public int MetadataFileOffset { get; } = metadataFileOffset;
            public int CorHeaderFileOffset { get; } = corHeaderFileOffset;
            public ImmutableArray<PeSection> Sections { get; } = sections;

            public static PeLayoutInfo Read(byte[] image)
            {
                int pe = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C, 4));
                if (pe < 0 || pe > image.Length - 24 || BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(pe, 4)) != 0x00004550)
                    throw new BadImageFormatException("Invalid PE signature.");

                int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 6, 2));
                int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(pe + 20, 2));
                int optional = pe + 24;
                int sectionTable = optional + optionalSize;
                ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(optional, 2));
                bool pe32Plus = magic == 0x20B;
                if (!pe32Plus && magic != 0x10B)
                    throw new BadImageFormatException("Unsupported PE optional header magic.");

                int sectionAlignment = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(optional + 32, 4));
                int fileAlignment = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(optional + 36, 4));
                int dataDirectory = optional + (pe32Plus ? 112 : 96);
                int cliDirectory = dataDirectory + (14 * 8);
                int corRva = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(cliDirectory, 4));

                ImmutableArray<PeSection>.Builder sections = ImmutableArray.CreateBuilder<PeSection>(sectionCount);
                for (int i = 0; i < sectionCount; i++)
                {
                    int sh = sectionTable + (i * 40);
                    sections.Add(new PeSection(
                        BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(sh + 8, 4)),
                        BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(sh + 12, 4)),
                        BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(sh + 16, 4)),
                        BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(sh + 20, 4))));
                }

                ImmutableArray<PeSection> sectionArray = sections.MoveToImmutable();
                ReadOnlySpan<PeSection> sectionSpan = sectionArray.AsSpan();
                if (sectionSpan.IsEmpty)
                    throw new BadImageFormatException("PE image contains no sections.");

                int firstRaw = int.MaxValue;
                int lastRawEnd = 0;
                int lastVirtualEnd = 0;
                foreach (ref readonly PeSection section in sectionSpan)
                {
                    if (section.RawPointer > 0 && section.RawPointer < firstRaw)
                        firstRaw = section.RawPointer;

                    lastRawEnd = Math.Max(lastRawEnd, checked(section.RawPointer + section.RawSize));
                    lastVirtualEnd = Math.Max(lastVirtualEnd, checked(section.VirtualAddress + Math.Max(section.VirtualSize, section.RawSize)));
                }

                if (firstRaw == int.MaxValue)
                    throw new BadImageFormatException("PE image contains no file-backed section.");

                PeLayoutInfo provisional = new(pe, optional, sectionTable, sectionCount, fileAlignment, sectionAlignment, firstRaw, lastRawEnd, lastVirtualEnd, 0, 0, sectionArray);
                if (!provisional.TryRvaToFileOffset(corRva, out int corOffset))
                    throw new BadImageFormatException("CLI header RVA is outside PE sections.");

                int metadataRva = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(corOffset + 8, 4));
                if (!provisional.TryRvaToFileOffset(metadataRva, out int metadataOffset))
                    throw new BadImageFormatException("Metadata RVA is outside PE sections.");

                return new PeLayoutInfo(pe, optional, sectionTable, sectionCount, fileAlignment, sectionAlignment, firstRaw, lastRawEnd, lastVirtualEnd, metadataOffset, corOffset, sectionArray);
            }

            public bool TryRvaToFileOffset(int rva, out int offset)
            {
                foreach (ref readonly PeSection section in Sections.AsSpan())
                {
                    int size = Math.Max(section.VirtualSize, section.RawSize);
                    if (rva >= section.VirtualAddress && rva < section.VirtualAddress + size)
                    {
                        offset = checked(section.RawPointer + (rva - section.VirtualAddress));
                        return true;
                    }
                }

                offset = -1;
                return false;
            }
        }

        private readonly record struct PeSection(int VirtualSize, int VirtualAddress, int RawSize, int RawPointer);

        private sealed class MetadataMethodRvaMap(
            int methodTableOffset,
            int methodRowSize,
            int methodRowCount)
        {
            private int MethodTableOffset { get; } = methodTableOffset;
            private int MethodRowSize { get; } = methodRowSize;
            private int MethodRowCount { get; } = methodRowCount;

            public static MetadataMethodRvaMap Read(byte[] image, int metadataOffset)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(metadataOffset, 4)) != 0x424A5342)
                    throw new BadImageFormatException("Invalid metadata signature.");

                int versionLength = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(metadataOffset + 12, 4));
                int cursor = Align(metadataOffset + 16 + versionLength, 4);
                cursor += 2;
                int streamCount = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(cursor, 2));
                cursor += 2;

                int tablesOffset = -1;
                for (int i = 0; i < streamCount; i++)
                {
                    int streamRelativeOffset = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(cursor, 4));
                    cursor += 8;
                    int nameStart = cursor;
                    while (cursor < image.Length && image[cursor] != 0)
                        cursor++;
                    string name = System.Text.Encoding.ASCII.GetString(image, nameStart, cursor - nameStart);
                    cursor = Align(cursor + 1, 4);
                    if (name is "#~" or "#-")
                        tablesOffset = checked(metadataOffset + streamRelativeOffset);
                }

                if (tablesOffset < 0)
                    throw new BadImageFormatException("Metadata tables stream (#~/#-) was not found.");

                byte heapSizes = image[tablesOffset + 6];
                ulong valid = BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(tablesOffset + 8, 8));
                int rowCursor = tablesOffset + 24;
                Span<int> rows = stackalloc int[64];
                for (int table = 0; table < rows.Length; table++)
                {
                    if ((valid & (1UL << table)) == 0)
                        continue;
                    rows[table] = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(rowCursor, 4));
                    rowCursor += 4;
                }

                int stringIndex = (heapSizes & 0x01) != 0 ? 4 : 2;
                int guidIndex = (heapSizes & 0x02) != 0 ? 4 : 2;
                int blobIndex = (heapSizes & 0x04) != 0 ? 4 : 2;
                int fieldIndex = TableIndexSize(rows, 4);
                int methodIndex = TableIndexSize(rows, 6);
                int paramIndex = TableIndexSize(rows, 8);

                ReadOnlySpan<int> sizes =
                [
                    2 + stringIndex + (guidIndex * 3),
                    CodedIndexSize(rows, 2, 0, 26, 35, 1) + (stringIndex * 2),
                    4 + (stringIndex * 2) + CodedIndexSize(rows, 2, 2, 1, 27) + fieldIndex + methodIndex,
                    fieldIndex,
                    2 + stringIndex + blobIndex,
                    methodIndex,
                    4 + 2 + 2 + stringIndex + blobIndex + paramIndex
                ];

                int methodTable = rowCursor;
                for (int table = 0; table < 6; table++)
                    methodTable = checked(methodTable + (rows[table] * sizes[table]));

                return new MetadataMethodRvaMap(methodTable, sizes[6], rows[6]);
            }

            public void WriteMethodRva(byte[] image, int metadataToken, int rva)
            {
                int row = metadataToken & 0x00FFFFFF;
                if (row <= 0 || row > MethodRowCount)
                    throw new BadImageFormatException($"MethodDef token 0x{metadataToken:X8} is outside MethodDef table bounds.");

                int offset = checked(MethodTableOffset + ((row - 1) * MethodRowSize));
                BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(offset, 4), rva);
            }

            private static int TableIndexSize(ReadOnlySpan<int> rows, int table) => rows[table] < 0x10000 ? 2 : 4;

            private static int CodedIndexSize(ReadOnlySpan<int> rows, int tagBits, params ReadOnlySpan<int> tables)
            {
                int maxRows = 0;
                foreach (int table in tables)
                    maxRows = Math.Max(maxRows, rows[table]);
                return maxRows < (1 << (16 - tagBits)) ? 2 : 4;
            }
        }
    }
}
