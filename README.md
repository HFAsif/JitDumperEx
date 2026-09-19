# JitDumperEx — Dump JIT-Generated Code via ExecuteEXE & ExecuteDLLForAttach

## Highlights

- CLR2 and CLR4 runtime handling across the .NET Framework 2.0–4.8 runtime family
- x86 and x64 architecture-specific builds
- `ExecuteEXE` and `ExecuteDLLForAttach` target loading paths
- Dynamic CLR pointer and `PEDecoder::IsILOnly` gate resolution instead of relying on fixed runtime RVAs where possible
- Hooks the first `ICorJitCompiler` vtable entry: `compileMethod`
- Captures target JIT method bodies and native JIT result information
- Recovers IL, exception-handler data, local signatures, `MaxStack`, initialization flags, and related metadata used during reconstruction
- Rebuilds captured methods into a dumped executable or assembly
- Displays raw IL, decoded IL, and experimental readable C# reconstruction
- Uses bounded `Parallel.ForEachAsync` processing for post-capture diagnostic rendering
- `EnableFastCallClr` compatibility support for **CLR4 x86 only**
- Uses the DotnetEx compatibility layer to make selected modern .NET APIs available to legacy .NET Framework targets

## Key APIs / Libraries Used

The project currently uses selected APIs and compatibility surfaces including:

- `System.Collections.Immutable`
- `System.Collections.Frozen`
- `System.Buffers`
- `System.Buffers.Binary`
- `System.Reflection.Metadata`
- `System.Reflection.PortableExecutable`
- `System.Runtime.CompilerServices.Unsafe`
- `System.Runtime.Loader`
- `Microsoft.Extensions.Logging.Abstractions`
- `Microsoft.CSharp`
- `HFDotnetEx.Helpers`

The project currently uses the **DotnetEx 4.1.60** compatibility stack. Direct project package references include:

- `HFDotnetEx.Helpers`
- `DotnetEx.Microsoft.CSharp.Ex`
- `DotnetEx.Microsoft.Extensions.Logging.Abstractions.Ex`
- `DotnetEx.System.Reflection.Metadata.Ex`
- `DotnetEx.System.Runtime.CompilerServices.Unsafe.Ex`
- `DotnetEx.System.Runtime.Loader.Ex`

## Runtime / Architecture Notes

- **Runtime family:** .NET Framework 2.0–4.8 through CLR2 / CLR4 paths
- **Current project TFMs:** `net20`, `net40`
- **Release architectures:** x86, x64
- **AnyCPU:** configured but not validated yet
- **FastCall compatibility:** CLR4 x86 only

## Project Status

The JIT dump and reconstruction pipeline is still under active development. It is intended for research, testing, and experimentation, and has not yet been fully validated across every CLR build, architecture, and protected or non-standard assembly.
