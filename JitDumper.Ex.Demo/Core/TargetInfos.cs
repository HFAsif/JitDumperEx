namespace LoaderExDemo
{
    internal sealed class TargetInfos
    {
        public bool LogEnable { get; set; }
        public bool Listasm { get; set; }
        public bool disposemoddef { get; set; }
        public bool AsmLoadLocation { get; set; }
        public bool showConsoleVurbos { get; set; }
        public bool OnFlyMode { get; set; }

        public EnumViews.AsmModuleHookType asmModuleHookType { get; set; }
        public EnumViews.AsmModuleCaller asmModuleCaller { get; set; }
        public EnumViews.AsmLoaders asmLoaders { get; set; }
        public EnumViews.LateInjectionType lateInjectionType { get; set; }
        public EnumViews.Offsets_Installed_Type offsets_Installed_Type { get; set; }

        public EnumViews.Native_Dll_Loaded_Type native_Dll_Loaded_Type = EnumViews.Native_Dll_Loaded_Type.JITEngineRelated;
        public EnumViews.Comjitsystm comjitsystm { get; set; }
        public EnumViews.SystemcompilerComcompiler SystemcompilerComcompilerIntLoadType { get; set; }
        public EnumViews.Jitclassloadsystem jitclassloadsystem { get; set; }
        public EnumViews.ImpImportLoadSystem ImpImportLoadSystem { get; set; }
        public EnumViews.ExeCuteSystem exeCuteSystem { get; set; }
        public EnumViews.ProcessInjectioType processInjectioType { get; set; }
        public EnumViews.CompilerExJitType compilerExJitType { get; set; }
        public EnumViews.CompilerExVersion compilerExVersion { get; set; }



        public bool ExeCution { get; set; }
        public bool exeCuteNativeWay { get; set; }
        public bool LoadAsmWithAsmModuleHook { get; set; }
        public bool exeCuteHookerSystemNativeWay { get; set; }
        public bool ExeRunningSystemManaged { get; set; }
        public bool OnflyRun_theoretical { get; set; }
        public bool exeCuteNativeCsharpRun { get; set; }

        public bool createtectFile;

        public int runtime_version;

        public const bool MlogEnable = true;
        public int Flag { get; set; }
        public bool PdbInstalled { get; set; }
        public bool EnableGuiLoad { get; set; }
        public bool AnciiClassUseAuto {  get; set; }

        public string[] args { get; set; } = [];

        public TargetInfos(/*string _FileName*/)
        {
            asmModuleHookType = EnumViews.AsmModuleHookType.NativeOne;
            SystemcompilerComcompilerIntLoadType = EnumViews.SystemcompilerComcompiler.ThirtyTwoBit;
            LoadAsmWithAsmModuleHook = true;
            exeCuteHookerSystemNativeWay = true;
            OnflyRun_theoretical = false;
            exeCuteNativeCsharpRun = false;
            ExeRunningSystemManaged = true;
            processInjectioType = EnumViews.ProcessInjectioType.Yck;
            OnFlyMode = false;
            AsmLoadLocation = false;
            disposemoddef = false;
            Listasm = false;
            exeCuteSystem = EnumViews.ExeCuteSystem.ExecuteTwo;
            exeCuteNativeWay = true;
            runtime_version = Environment.Version.Major;
            asmLoaders = EnumViews.AsmLoaders.AsmJITNative;
            comjitsystm = EnumViews.Comjitsystm.SystemcompilerSix;
            jitclassloadsystem = EnumViews.Jitclassloadsystem.Direct;
            ImpImportLoadSystem = EnumViews.ImpImportLoadSystem.ImpImportSystemOne;
            createtectFile = false;
            asmModuleCaller = EnumViews.AsmModuleCaller.StdCall;
            offsets_Installed_Type = EnumViews.Offsets_Installed_Type.Csharp;
            native_Dll_Loaded_Type = EnumViews.Native_Dll_Loaded_Type.JITEngineCdcl;
            showConsoleVurbos = true;
            EnableGuiLoad = true;
            AnciiClassUseAuto = false;
            compilerExJitType = EnumViews.CompilerExJitType.Default;
            compilerExVersion = EnumViews.CompilerExVersion.Two;
            lateInjectionType = EnumViews.LateInjectionType.Detour;
            ExeCution = false;
            LogEnable = true;
        }

    }
}
