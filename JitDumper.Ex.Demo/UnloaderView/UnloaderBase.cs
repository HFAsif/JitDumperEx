using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Base pipeline for JIT capture and rebuild.")]
    internal abstract class UnloaderBase
    {
        public const int FLAG_None = 0;
        public const int FLAG_VMP_V35 = 1;
        public const int FLAG_VMP_V36 = 2;

        protected Assembly? assembly;
        protected string? targetPath;
        protected Action<string>? log;
        protected int flag;

        protected Assembly TargetAssembly => assembly ?? throw new InvalidOperationException("Target assembly is not initialized.");
        protected string TargetPath => targetPath ?? throw new InvalidOperationException("Target output path is not initialized.");
        protected Action<string> Log => log ?? throw new InvalidOperationException("JIT dump logger is not initialized.");

        public abstract void JitDump(Assembly assembly, string targetPath, Action<string> log, int flag);

        protected static void LogException(Exception ex)
        {
            ArgumentNullException.ThrowIfNull(ex);
            ThisStaticClass.Logger.LogError(ex, "Unhandled LoaderExDemo exception");
        }

        [HelperClass.SomeElementsInfos("Maps target method handles from metadata.")]
        protected unsafe JitMethodTable GetMethodTable()
        {
            string sourcePath = TargetAssembly.Location;
            if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
                throw new FileNotFoundException("The loaded target assembly does not expose a valid on-disk location.", sourcePath);

            Module module = TargetAssembly.ManifestModule;
            ModuleHandle moduleHandle = module.ModuleHandle;
            byte[] metadataBytes = GetRawMetadataBytes(TargetAssembly);

            using FileStream stream = File.OpenRead(sourcePath);
            using PEReader peReader = new(stream);
            MetadataReader sourceMetadata = peReader.GetMetadataReader();

            RuntimeMethodHandle[] methodHandles;
            Dictionary<nint, JitMethodDescriptor> byHandle = new();

            fixed (byte* metadataBlob = metadataBytes)
            {
                MetadataReader metadata = new(metadataBlob, metadataBytes.Length);
                methodHandles = new RuntimeMethodHandle[metadata.MethodDefinitions.Count];

                foreach (MethodDefinitionHandle methodHandle in metadata.MethodDefinitions)
                {
                    int rowId = MetadataTokens.GetRowNumber(methodHandle);
                    int token = MetadataTokens.GetToken(methodHandle);

                    try
                    {
                        MethodDefinition definition = metadata.GetMethodDefinition(methodHandle);
                        if (definition.RelativeVirtualAddress == 0)
                            continue;

                        RuntimeMethodHandle runtimeHandle = moduleHandle.ResolveMethodHandle(token);
                        if (runtimeHandle.Value == IntPtr.Zero)
                            continue;

                        MethodBase? method = module.ResolveMethod(token);
                        if (method is null || method.IsAbstract)
                            continue;

                        MethodDefinition sourceDefinition = sourceMetadata.GetMethodDefinition(methodHandle);
                        JitMethodBodyMetadata body = ReadMethodBodyMetadata(peReader, sourceDefinition);
                        methodHandles[rowId - 1] = runtimeHandle;
                        byHandle[(nint)runtimeHandle.Value] = new JitMethodDescriptor(token, rowId, runtimeHandle, method, body);
                    }
                    catch (Exception ex)
                    {
                        ThisStaticClass.Logger.LogDebug(ex, "[JIT-TABLE] Skipped MethodDef token 0x{Token:X8}", token);
                    }
                }
            }

            ThisStaticClass.Logger.LogInformation("[JIT-TABLE] RawMetadata={RawMetadataBytes} bytes; MethodDef rows={Rows}; resolvable={Resolvable}", metadataBytes.Length, methodHandles.Length, byHandle.Count);
            return new JitMethodTable(
                ImmutableCollectionsMarshal.AsImmutableArray(methodHandles),
                byHandle.ToFrozenDictionary());
        }

        private static unsafe byte[] GetRawMetadataBytes(Assembly assembly)
        {
            ArgumentNullException.ThrowIfNull(assembly);



            if (!assembly.TryGetRawMetadata(out byte* blob, out int length) || blob == null || length <= 0)
                throw new BadImageFormatException("Unable to retrieve raw metadata from the loaded target assembly.");

            return new ReadOnlySpan<byte>(blob, length).ToArray();
        }

        protected void SendToJitSMD(JitMethodTable methodTable)
        {
            ArgumentNullException.ThrowIfNull(methodTable);

            MethodInfo compileMethod = typeof(RuntimeHelpers).GetMethod("_CompileMethod", BindingFlags.Instance | BindingFlags.Static | BindingFlags.NonPublic)
                ?? throw new MissingMethodException(typeof(RuntimeHelpers).FullName, "_CompileMethod");

            ParameterInfo[] parameters = compileMethod.GetParameters();
            if (parameters.Length != 1)
                throw new MissingMethodException("RuntimeHelpers._CompileMethod has an unexpected signature.");

            Type parameterType = parameters[0].ParameterType;
            ReadOnlySpan<RuntimeMethodHandle> methodHandles = methodTable.MethodHandles.AsSpan();

            for (int i = 0; i < methodHandles.Length; i++)
            {
                RuntimeMethodHandle handle = methodHandles[i];
                if (handle.Value == IntPtr.Zero || !methodTable.ByHandle.TryGetValue((nint)handle.Value, out JitMethodDescriptor descriptor))
                    continue;

                try
                {
                    SendToJitSMD(handle, descriptor.Method, compileMethod, parameterType);
                }
                catch (Exception ex)
                {
                    ThisStaticClass.Logger.LogWarning(ex, "[JIT-BUMP] Failed token 0x{Token:X8} ({Method})", descriptor.MetadataToken, descriptor.Method);
                }
            }
        }

        private static void SendToJitSMD(RuntimeMethodHandle handle, MethodBase method, MethodInfo compileMethod, Type parameterType)
        {
            try
            {
                RuntimeHelpers.PrepareMethod(handle);
                return;
            }
            catch (Exception prepareException)
            {
                ThisStaticClass.Logger.LogDebug(prepareException, "[JIT-BUMP] RuntimeHelpers.PrepareMethod failed; using RuntimeHelpers._CompileMethod for {Method}", method);
            }

            try
            {
                object argument = parameterType == typeof(IntPtr)
                    ? handle.Value
                    : parameterType == typeof(RuntimeMethodHandle)
                        ? handle
                        : string.Equals(parameterType.FullName, "System.IRuntimeMethodInfo", StringComparison.Ordinal)
                            ? method
                            : throw new NotSupportedException($"Unsupported RuntimeHelpers._CompileMethod parameter type: {parameterType.FullName}");

                compileMethod.Invoke(null, [argument]);
            }
            catch (TargetInvocationException invocation)
            {
                Exception? innerException = invocation.InnerException;
                if (innerException is null)
                    throw;

                throw innerException;
            }
        }

        private static JitMethodBodyMetadata ReadMethodBodyMetadata(PEReader peReader, MethodDefinition definition)
        {
            if (definition.RelativeVirtualAddress == 0)
                return JitMethodBodyMetadata.Empty;

            try
            {
                MethodBodyBlock body = peReader.GetMethodBody(definition.RelativeVirtualAddress);
                ImmutableArray<JitExceptionRegion>.Builder regions = ImmutableArray.CreateBuilder<JitExceptionRegion>(body.ExceptionRegions.Length);

                foreach (ref readonly ExceptionRegion region in body.ExceptionRegions.AsSpan())
                {
                    JitExceptionRegionKind kind = region.Kind switch
                    {
                        ExceptionRegionKind.Catch => JitExceptionRegionKind.Catch,
                        ExceptionRegionKind.Filter => JitExceptionRegionKind.Filter,
                        ExceptionRegionKind.Finally => JitExceptionRegionKind.Finally,
                        ExceptionRegionKind.Fault => JitExceptionRegionKind.Fault,
                        _ => throw new BadImageFormatException($"Unknown exception region kind {region.Kind}.")
                    };

                    int catchTypeToken = region.Kind == ExceptionRegionKind.Catch && !region.CatchType.IsNil ? MetadataTokens.GetToken(region.CatchType) : 0;
                    int filterOffset = region.Kind == ExceptionRegionKind.Filter ? region.FilterOffset : 0;
                    regions.Add(new JitExceptionRegion(kind, region.TryOffset, region.TryLength, region.HandlerOffset, region.HandlerLength, catchTypeToken, filterOffset));
                }

                int localSignatureToken = body.LocalSignature.IsNil ? 0 : MetadataTokens.GetToken(body.LocalSignature);
                return new JitMethodBodyMetadata(body.MaxStack, body.LocalVariablesInitialized, localSignatureToken, regions.MoveToImmutable());
            }
            catch (Exception ex)
            {
                ThisStaticClass.Logger.LogDebug(ex, "[JIT-TABLE] Unable to read baseline method body metadata at RVA 0x{Rva:X8}", definition.RelativeVirtualAddress);
                return JitMethodBodyMetadata.Empty;
            }
        }
    }
}
