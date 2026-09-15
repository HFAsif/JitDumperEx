using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Core CLR load and dump workflow.")]
    internal static class StaticMethods
    {
        public static void jitDump_Click_Internal(Assembly assembly, string fileName, Action<string> log, int flag)
        {


            UnloaderBase jitdumper = ThisStaticClass.targetInfos.compilerExJitType switch
            {
                EnumViews.CompilerExJitType.Default => new DefaultUnloader(),
                _ => throw new NotImplementedException("Unsupported compilerExJitType: " + ThisStaticClass.targetInfos.compilerExJitType)
            };

            jitdumper.JitDump(assembly, fileName, log, flag);
        }
        public static string OutTarget(out string testTargetFile, out string testTargetFileOut)
        {
            var currentDir = Path.Combine(HelperClass.All.HelperViewsStatic.GetSolutionPath(), "VarifiedTargets");
            if (!Directory.Exists(currentDir))
            {
                Debugger.Break();
                throw new FileNotFoundException("VarifiedTargets directory not found: " + currentDir);
            }

            testTargetFile = ThisStaticClass.RuntimeKeyStatic switch
            {
                42 => $"{currentDir}\\net20\\x86\\WindowsFormsApp1.exe",
                44 => $"{currentDir}\\net40\\x86\\WindowsFormsApplication4.vmp35-decrypted-demutate-cleaned.justify_nodel.exe",
                82 => $"{currentDir}\\net20\\x64\\WindowsFormsApp1.exe",
                84 => $"{currentDir}\\net40\\x64\\TestProtect.exe",
                _ => throw new NotSupportedException($"Unsupported CLR/architecture combination. RuntimeKey={ThisStaticClass.RuntimeKeyStatic}")
            };
            testTargetFileOut = BuildJitDumpPath(testTargetFile);
            return testTargetFile;
        }

        internal static string BuildJitDumpPath(string targetPath)
        {
            if (string.IsNullOrWhiteSpace(targetPath))
                throw new ArgumentException("Target path cannot be null or whitespace.", nameof(targetPath));

            string directory = Path.GetDirectoryName(targetPath) ?? string.Empty;
            string fileName = Path.GetFileNameWithoutExtension(targetPath);
            string extension = Path.GetExtension(targetPath);
            string outputName = fileName + "_JitDumped" + extension;

            return directory.Length == 0 ? outputName : Path.Combine(directory, outputName);
        }

        public static unsafe IntPtr FindTestEaxAfterCall(IntPtr callSite)
        {
            byte* p = (byte*)callSite.ToPointer();

            if (p == null || *p != 0xE8)
                return IntPtr.Zero;




            p += 5;





            for (int i = 0; i < 16; i++)
            {
                if (p[i] == 0x85 && p[i + 1] == 0xC0)
                {
                    return (IntPtr)(p + i);
                }
            }

            return IntPtr.Zero;
        }

        public static unsafe IntPtr GetJccAfterTestEax(IntPtr testEaxAddress)
        {
            if (testEaxAddress == IntPtr.Zero)
                return IntPtr.Zero;

            byte* p = (byte*)testEaxAddress.ToPointer();


            if (p[0] != 0x85 || p[1] != 0xC0)
                return IntPtr.Zero;

            byte* jcc = p + 2;




            if (jcc[0] == 0x74 || jcc[0] == 0x75)
            {
                return (IntPtr)jcc;
            }




            if (jcc[0] == 0x0F && (jcc[1] == 0x84 || jcc[1] == 0x85))
            {
                return (IntPtr)jcc;
            }

            return IntPtr.Zero;
        }

        public static IntPtr GetPFileAddress(Assembly assembly)
        {
            ArgumentNullException.ThrowIfNull(assembly);

#if NET40_OR_GREATER
            FieldInfo? field = assembly.GetType().GetField("m_assembly", BindingFlags.Instance | BindingFlags.NonPublic);
#else
            FieldInfo? field = typeof(Assembly).GetField("m__assembly", BindingFlags.Instance | BindingFlags.NonPublic);
#endif

            if (field == null)
                return IntPtr.Zero;

            object? domainAssembly = field.GetValue(assembly);
            if (domainAssembly is not IntPtr pDomainAssembly)
                return IntPtr.Zero;

            if (pDomainAssembly == IntPtr.Zero)
                return IntPtr.Zero;





            return Marshal.ReadIntPtr(pDomainAssembly, IntPtr.Size * 2);

        }


        [HelperClass.SomeElementsInfos("Resolves CLR gates and starts dumping.")]
        public static void PrepareTargetAndLoadUnloadEventArgs(string testTargetFile, string testTargetFileOutput, bool execute)
        {
            PointerInfos pointerInfos = new();

            if (!pointerInfos.Resolve())
                throw new InvalidOperationException("Primary CLR pointer resolution failed.");

            pointerInfos.Print();

            PEDecoderIsILOnly peDecoderIsILOnly = new();
            peDecoderIsILOnly.Resolve(pointerInfos);
            peDecoderIsILOnly.Print();

            if (!peDecoderIsILOnly.IsResolved)
            {
                throw new InvalidOperationException("CLR ILONLY gate resolution failed.");
            }

            if (peDecoderIsILOnly.RuntimeKey == 42)
            {
                if (!peDecoderIsILOnly.IsInline || peDecoderIsILOnly.ResultCheck == IntPtr.Zero || peDecoderIsILOnly.ResultJcc == IntPtr.Zero)
                {
                    throw new InvalidOperationException("CLR2 x86 inline ILONLY gate was not resolved correctly.");
                }

                ThisStaticClass.Logger.LogInformation("CLR2 x86 inline ILONLY gate resolved successfully.");
            }
            else if (peDecoderIsILOnly.RuntimeKey == 82)
            {
                if (peDecoderIsILOnly.IsInline || peDecoderIsILOnly.IsILOnlyCallSite == IntPtr.Zero || peDecoderIsILOnly.IsILOnly == IntPtr.Zero || peDecoderIsILOnly.ResultCheck == IntPtr.Zero || peDecoderIsILOnly.ResultJcc == IntPtr.Zero)
                {
                    throw new InvalidOperationException("CLR2 x64 PEDecoder::IsILOnly gate was not resolved correctly.");
                }

                ThisStaticClass.Logger.LogInformation("CLR2 x64 PEDecoder::IsILOnly gate resolved successfully.");
            }

            ThisStaticClass.Logger.LogInformation("ILONLY resolver state: RuntimeKey={RuntimeKey}, IsResolved={IsResolved}, IsInline={IsInline}, "
                + "IsILOnlyCallSite=0x{IsILOnlyCallSite:X}, IsILOnly=0x{IsILOnly:X}, " + "ResultCheck=0x{ResultCheck:X}, ResultJcc=0x{ResultJcc:X}",
                peDecoderIsILOnly.RuntimeKey, peDecoderIsILOnly.IsResolved, peDecoderIsILOnly.IsInline, NativeAddressValue(peDecoderIsILOnly.IsILOnlyCallSite),
                NativeAddressValue(peDecoderIsILOnly.IsILOnly), NativeAddressValue(peDecoderIsILOnly.ResultCheck), NativeAddressValue(peDecoderIsILOnly.ResultJcc));


            var assembly = LoadAssembly(testTargetFile, peDecoderIsILOnly.ResultJcc, true, execute, pointerInfos);

            jitDump_Click_Internal(assembly, testTargetFileOutput, message => ThisStaticClass.Logger.LogInformation(message), UnloaderBase.FLAG_None);
        }

        internal static ulong NativeAddressValue(nint value) => IntPtr.Size == 8 ? unchecked((ulong)(long)value) : unchecked((uint)(int)value);

        [HelperClass.SomeElementsInfos("Loads target through patched ILOnly gate.")]
        public static Assembly LoadAssembly(string targetFile, IntPtr isILOnlyJcc, bool enableX86Patch, bool isExecuteExe, PointerInfosBase ptrs)
        {
            ArgumentNullException.ThrowIfNull(ptrs, nameof(ptrs));
            Assembly? targetAssembly = null;
            string targetAssemblyName = AssemblyName.GetAssemblyName(targetFile).Name ?? throw new BadImageFormatException("Target assembly has no simple name.");
            using ManualResetEvent assemblyLoaded = new(false);

            void OnAssemblyLoad(object? sender, AssemblyLoadEventArgs e)
            {
                Assembly asm = e.LoadedAssembly;

                if (asm == null)
                    return;

                try
                {
                    ThisStaticClass.Logger.LogInformation("[ASMLOAD] {AssemblyFullName}", asm.FullName);

                    string? name = asm.GetName().Name;

                    if (string.Equals(name, targetAssemblyName, StringComparison.OrdinalIgnoreCase))
                    {
                        targetAssembly = asm;

                        ThisStaticClass.Logger.LogInformation("[ASMLOAD] TARGET CAPTURED: {AssemblyFullName}", asm.FullName);


                        assemblyLoaded.Set();

                        if (isExecuteExe)
                        {
                            ThisStaticClass.Logger.LogInformation("[ASMLOAD] Target assembly loaded after ExecuteExe. You works will do here ");
                            ThisStaticClass.Logger.LogInformation("[ASMLOAD] ========================================================== ");
                            ThisStaticClass.Logger.LogInformation("[ASMLOAD] Press enter to run the application ");

                        }
                    }
                }
                catch (Exception ex)
                {
                    ThisStaticClass.Logger.LogError(ex, "[ASMLOAD] Failed while processing AssemblyLoad event");
                }
            }

            AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;

            byte[]? originalIlOnlyGate = null;
            bool ilOnlyPatched = false;

            try
            {



                switch (ptrs.RuntimeKey)
                {
                    case 42:
                    case 44:
                        if (enableX86Patch)
                        {
                            originalIlOnlyGate = AllPatches.PatchIlOnlyGateUniversal(isILOnlyJcc);
                            ilOnlyPatched = true;
                        }
                        break;

                    case 82:
                    case 84:
                        originalIlOnlyGate = AllPatches.PatchIlOnlyGateUniversal(isILOnlyJcc);
                        ilOnlyPatched = true;
                        break;

                    default: throw new NotSupportedException("Unsupported RuntimeKey=" + ptrs.RuntimeKey);
                }


                ExeLoader.ExecuteExe(targetFile, isExecuteExe, ptrs.ExecuteEXE, ptrs.ExecuteDLLForAttach);

                assemblyLoaded.WaitOne();














            }
            finally
            {

                if (ilOnlyPatched && originalIlOnlyGate != null)
                {
                    AllPatches.RestoreBytes(isILOnlyJcc, originalIlOnlyGate);
                }

                AppDomain.CurrentDomain.AssemblyLoad -= OnAssemblyLoad;
            }

            Assembly? asm = targetAssembly;

            if (asm is null)
            {
                throw new InvalidOperationException("Target assembly was not captured.");
            }

            ThisStaticClass.Logger.LogInformation("[SUCCESS] {AssemblyFullName}", asm.FullName);


            return asm;
        }

    }
}
