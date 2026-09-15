using System.Collections.Immutable;

namespace LoaderExDemo
{
    internal delegate void JitMethodCallback(in JitMethodContext context);

    [HelperClass.SomeElementsInfos("JIT hook lifecycle contract.")]
    internal interface IHooker : IDisposable, IAsyncDisposable
    {
        bool IsHooked { get; }

        void Hook();
        void Hook(JitMethodCallback callback);
        void UnHook();
    }

    internal readonly ref struct JitMethodContext(
        nint methodHandle,
        ImmutableArray<byte> ilBytes,
        uint maxStack,
        uint ehCount,
        uint options,
        ReadOnlySpan<JitExceptionRegion> exceptionRegions,
        bool exceptionRegionsFromJit,
        nint nativeEntry,
        uint nativeSizeOfCode,
        uint jitResult)
    {
        public nint MethodHandle { get; } = methodHandle;
        public ImmutableArray<byte> ILBytes { get; } = ilBytes;
        public ReadOnlySpan<byte> ILCode => ILBytes.AsSpan();
        public uint MaxStack { get; } = maxStack;
        public uint EHCount { get; } = ehCount;
        public uint Options { get; } = options;
        public ReadOnlySpan<JitExceptionRegion> ExceptionRegions { get; } = exceptionRegions;
        public bool ExceptionRegionsFromJit { get; } = exceptionRegionsFromJit;
        public nint NativeEntry { get; } = nativeEntry;
        public uint NativeSizeOfCode { get; } = nativeSizeOfCode;
        public uint JitResult { get; } = jitResult;
    }
}
