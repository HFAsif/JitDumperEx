# LoaderExDemo
## 2026-09-15 JIT safety + HQ C# 14 / DotnetEx future pass

- Targets remain `net20;net40` with C# 14 and AnyCPU/x86/x64 configurations.
- DotnetEx package references remain on the attached project's `4.1.45` baseline; this pass does not change dependency ownership or package versions.
- The unmanaged JIT ABI path stays strongly typed. `ICorJitCompiler::compileMethod` keeps the Microsoft `__stdcall` contract and the original JIT is called exactly once per intercepted compilation.
- The original `compileMethod` target is reached through a permanent native trampoline; hook installation pre-prepares the managed delegates before the JIT vtable is changed.
- Trampoline memory is owned by a `SafeHandle`; native page-protection mutation and restoration use CER/reliability patterns, and unmanaged-call stack-walk suppression is limited to internal full-trust interop boundaries.
- CLR2/CLR4 `CORINFO_METHOD_INFO` tail fields are read from the end of `ILCodeSize`, avoiding x64 managed-struct padding assumptions. Unsafe hard-coded direct `ICorJitInfo` EH vtable calls are not used; metadata remains the safe EH fallback.
- `Assembly.TryGetRawMetadata(out byte* blob, out int length)` -> copied metadata -> `MetadataReader` -> row-indexed `RuntimeMethodHandle[]` remains the method-table path.
- `RuntimeHelpers.PrepareMethod` remains the primary JIT trigger with private `_CompileMethod` fallback resolved once per session.
- Captured method data is persisted before IL diagnostic formatting so a logging/decoder failure cannot discard a valid JIT snapshot.
- Modernization uses C# 13/14 language contracts and verified DotnetEx 4.1.45 future surfaces where they improve real code paths: `field`, primary constructors, records, collection expressions, C# 13 `params ReadOnlySpan<T>`, `Span`/`ReadOnlySpan`, `SearchValues<T>`, range-search extensions, `ArrayPool<T>`, `BinaryPrimitives`, `ImmutableArray<T>`, `ImmutableCollectionsMarshal`, `FrozenDictionary`/`FrozenSet`, and `Unsafe`.
- JIT IL capture now transfers a newly-owned byte array into `ImmutableArray<byte>` through `ImmutableCollectionsMarshal.AsImmutableArray`, avoiding a second full IL-body copy while preserving immutable snapshot ownership.
- Bounded CLR code scanners use pooled byte buffers plus span views; NOP/INT3 padding scans use the v10-style `SearchValues<byte>`/`IndexOfAnyExcept` surface instead of repeated ad-hoc comparisons.
- Repeated JIT method-handle lookups are frozen once into `FrozenDictionary<nint, JitMethodDescriptor>` after discovery.
- String literal diagnostics use a `SearchValues<char>` fast path and the future span range-search APIs before falling back to the exact escaping path.
- `System.Dynamic` remains intentionally confined to runtime diagnostics (`dynamic` + `ExpandoObject`) and is not moved into the ABI-critical JIT/native hook path.
- No third-party library/code was added.
- Progress-bar / Task / bounded `Parallel.ForEachAsync` orchestration is intentionally not part of this pass; it is reserved for the final progress pass.
