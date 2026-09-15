using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Reflection;

namespace LoaderExDemo
{
    internal enum JitExceptionRegionKind
    {
        Catch,
        Filter,
        Finally,
        Fault
    }

    internal readonly record struct JitExceptionRegion(
        JitExceptionRegionKind Kind,
        int TryOffset,
        int TryLength,
        int HandlerOffset,
        int HandlerLength,
        int CatchTypeToken,
        int FilterOffset);

    internal readonly record struct JitMethodBodyMetadata(
        int MaxStack,
        bool InitLocals,
        int LocalSignatureToken,
        ImmutableArray<JitExceptionRegion> ExceptionRegions)
    {
        public static JitMethodBodyMetadata Empty => new(8, false, 0, ImmutableArray<JitExceptionRegion>.Empty);
    }

    internal readonly record struct JitMethodDescriptor(
        int MetadataToken,
        int RowId,
        RuntimeMethodHandle MethodHandle,
        MethodBase Method,
        JitMethodBodyMetadata BaselineBody);

    [HelperClass.SomeElementsInfos("Maps runtime method handles to descriptors.")]
    internal sealed class JitMethodTable(
        ImmutableArray<RuntimeMethodHandle> methodHandles,
        FrozenDictionary<nint, JitMethodDescriptor> byHandle)
    {
        public ImmutableArray<RuntimeMethodHandle> MethodHandles { get; } = methodHandles;
        public FrozenDictionary<nint, JitMethodDescriptor> ByHandle { get; } = byHandle;
    }

    internal readonly record struct JitMethodSnapshot(
        int MetadataToken,
        int RowId,
        ImmutableArray<byte> ILCode,
        uint MaxStack,
        uint EHCount,
        int LocalSignatureToken,
        bool InitLocals,
        ImmutableArray<JitExceptionRegion> ExceptionRegions);
}
