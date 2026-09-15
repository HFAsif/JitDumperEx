using System.Collections.Immutable;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    internal sealed class DefaultUnloader : UnloaderBase
    {
        private const uint CorInfoOptInitLocals = 0x00000010;

        private readonly object _captureLock = new();
        private readonly Dictionary<int, JitMethodSnapshot> _capturedMethods = new();
        private JitMethodTable? _methodTable;

        public override void JitDump(Assembly assembly, string targetPath, Action<string> log, int flag)
        {
            ArgumentNullException.ThrowIfNull(assembly);
            if (string.IsNullOrWhiteSpace(targetPath))
                throw new ArgumentException("Output path is required.", nameof(targetPath));
            ArgumentNullException.ThrowIfNull(log);

            this.assembly = assembly;
            this.targetPath = targetPath;
            this.log = log;
            this.flag = flag;

            lock (_captureLock)
                _capturedMethods.Clear();

            Thread thread = new(JitDumpCore) { Name = "LoaderExDemo.JitDump" };
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
        }

        private void JitDumpCore()
        {
            try
            {
                nint pFileAddress = StaticMethods.GetPFileAddress(TargetAssembly);
                ThisStaticClass.Logger.LogInformation("[GetPFileAddress] 0x{Address:X}", StaticMethods.NativeAddressValue(pFileAddress));

                _methodTable = GetMethodTable();
                DefaultHooker.Initialize();

                using IHooker defaultHooker = new DefaultHooker();
                defaultHooker.Hook(OnJitMethod);

                try
                {
                    SendToJitSMD(_methodTable);
                }
                finally
                {
                    defaultHooker.UnHook();
                }

                JitMethodSnapshot[] capturedMethods;
                lock (_captureLock)
                    capturedMethods = [.. _capturedMethods.Values];

                JitTargetRebuilder.Rebuild(TargetAssembly.Location, TargetPath, capturedMethods);
                Log($"[JIT-DUMP] Completed. Captured={capturedMethods.Length}; Output={TargetPath}");
            }
            catch (Exception ex)
            {
                LogException(ex);
                Log($"[JitDumpCore] Exception: {ex}");
            }
        }

        private void OnJitMethod(in JitMethodContext context)
        {
            JitMethodTable methodTable = _methodTable ?? throw new InvalidOperationException("JIT method table is not initialized.");
            if (!methodTable.ByHandle.TryGetValue(context.MethodHandle, out JitMethodDescriptor descriptor))
            {
                ThisStaticClass.Logger.LogDebug("[JIT] Ignored non-target MethodHandle=0x{MethodHandle:X}", StaticMethods.NativeAddressValue(context.MethodHandle));
                return;
            }

            JitMethodBodyMetadata body = ResolveBodyMetadata(descriptor, in context);
            JitMethodSnapshot snapshot = new(
                descriptor.MetadataToken,
                descriptor.RowId,
                context.ILBytes,
                checked((uint)Math.Max(body.MaxStack, 0)),
                context.EHCount,
                body.LocalSignatureToken,
                body.InitLocals,
                body.ExceptionRegions);



            lock (_captureLock)
                _capturedMethods[descriptor.MetadataToken] = snapshot;

            try
            {
                JitIlDecoder.LogMethod(descriptor, in context, in body);
            }
            catch (Exception ex)
            {
                try
                {
                    ThisStaticClass.Logger.LogWarning(ex, "[JIT-IL] Decode/logging failed for token 0x{Token:X8}; captured body retained.", descriptor.MetadataToken);
                }
                catch
                {
                }
            }
        }

        private static JitMethodBodyMetadata ResolveBodyMetadata(JitMethodDescriptor descriptor, in JitMethodContext context)
        {
            JitMethodBodyMetadata baseline = descriptor.BaselineBody;
            ImmutableArray<JitExceptionRegion> regions = baseline.ExceptionRegions;

            if (context.EHCount == 0)
            {
                regions = ImmutableArray<JitExceptionRegion>.Empty;
            }
            else if (context.ExceptionRegionsFromJit && context.ExceptionRegions.Length == checked((int)context.EHCount))
            {
                regions = ImmutableArray.Create(context.ExceptionRegions);
            }
            else
            {
                try
                {
                    ThisStaticClass.Logger.LogDebug("[JIT-EH] Token=0x{Token:X8} direct JIT EH capture unavailable; using metadata fallback.", descriptor.MetadataToken);
                }
                catch
                {
                }
            }

            if ((uint)regions.Length != context.EHCount)
            {
                try
                {
                    ThisStaticClass.Logger.LogWarning("[JIT-EH] Token=0x{Token:X8} JIT EHCount={JitEhCount}, recoverable EH={RecoveredEhCount}; rebuild will skip this method.", descriptor.MetadataToken, context.EHCount, regions.Length);
                }
                catch
                {
                }
            }

            int maxStack = context.MaxStack == 0 ? baseline.MaxStack : checked((int)context.MaxStack);
            bool initLocals = (context.Options & CorInfoOptInitLocals) != 0 || baseline.InitLocals;
            return new JitMethodBodyMetadata(maxStack, initLocals, baseline.LocalSignatureToken, regions);
        }
    }
}
