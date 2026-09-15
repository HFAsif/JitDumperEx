namespace LoaderExDemo
{
    internal static class EnumViews
    {

        [Flags()]
        public enum ImageMemoryKind
        {
            Invalid,
            FlatPrivate,
            MappedFile,
            MappedImage
        }


        [Flags]
        public enum PeLayout
        {
            Unknown,
            Flat,
            Mapped,
            Both
        }

        [Flags]
        public enum MemoryKind
        {
            Invalid,
            Free,
            Reserved,
            Image,
            MappedFile,
            PrivateMemory
        };

        public enum ProcessInjectioType
        {
            Yck,
            NewSystem
        }

        public enum AsmModuleHookType
        {
            NativeOne,
            CsharpOne
        }

        public enum ExeLoadSystem
        {
            One,
            Two,
            Three,
            Four,
            Five,
        }

        public enum CompilerExVersion
        {
            One,
            Two
        }

        public enum CompilerExJitType
        {
            CompilerComViewInit,
            impImportUnloader,
            ICorProfilerUnloader,
            ICorProfilerUnloaderTwo,
            CompilerComMethodUnloader,
            VmpUnloader,
            Default
        }

        public enum SystemcompilerComcompiler
        {
            ThirtyTwoBit,
            SixtyFourBit,
            AnyCPU,
        }

        public enum Comjitsystm
        {
            SystemcomvoidOriginal,
            SystemcompilerTwo,
            SystemcompilerThree,
            SystemcompilerFour,
            SystemcompilerFive,
            SystemcompilerSix,
            SystemcompilerComcompilerAnyCPU,
            SystemcompilerComcompilerThirtyTwoBit
        };

        public enum Jitclassloadsystem
        {
            Direct,
            Normal
        };

        public enum ImpImportLoadSystem
        {
            ImpImportSystemOne,
            ImpImportSystemTwo
        }

        public enum NativeLoadSystem
        {
            ExeLoaderNative,
            UnknowLoaderNative
        }

        public enum AsmModuleCaller
        {
            StdCall,
            Cdecl
        };

        public enum LateInjectionType
        {
            Detour,
            NoDetour
        };

        public enum AsmLoaders
        {
            NormalLoad,
            AsmJITNative,
            AsmJITCSharp
        };

        public enum Offsets_Installed_Type
        {
            Csharp,
            Native
        };

        public enum Native_Dll_Loaded_Type
        {
            JITEngineStd,
            JITEngineCdcl,
            JITEngineRelated,
            All
        };

        public enum ExeCuteSystem
        {
            ExecuteOne, ExecuteTwo
        };

        [Flags()]
        public enum VirtualAlloc_AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags()]
        public enum VirtualAlloc_MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }


        public enum _IMAGEHLP_SYMBOL_TYPE_INFO
        {
            TI_GET_SYMTAG,
            TI_GET_SYMNAME,
            TI_GET_LENGTH,
            TI_GET_TYPE,
            TI_GET_TYPEID,
            TI_GET_BASETYPE,
            TI_GET_ARRAYINDEXTYPEID,
            TI_FINDCHILDREN,
            TI_GET_DATAKIND,
            TI_GET_ADDRESSOFFSET,
            TI_GET_OFFSET,
            TI_GET_VALUE,
            TI_GET_COUNT,
            TI_GET_CHILDRENCOUNT,
            TI_GET_BITPOSITION,
            TI_GET_VIRTUALBASECLASS,
            TI_GET_VIRTUALTABLESHAPEID,
            TI_GET_VIRTUALBASEPOINTEROFFSET,
            TI_GET_CLASSPARENTID,
            TI_GET_NESTED,
            TI_GET_SYMINDEX,
            TI_GET_LEXICALPARENT,
            TI_GET_ADDRESS,
            TI_GET_THISADJUST,
            TI_GET_UDTKIND,
            TI_IS_EQUIV_TO,
            TI_GET_CALLING_CONVENTION,
            TI_IS_CLOSE_EQUIV_TO,
            TI_GTIEX_REQS_VALID,
            TI_GET_VIRTUALBASEOFFSET,
            TI_GET_VIRTUALBASEDISPINDEX,
            TI_GET_IS_REFERENCE,
            TI_GET_INDIRECTVIRTUALBASECLASS,
            TI_GET_VIRTUALBASETABLETYPE,
            IMAGEHLP_SYMBOL_TYPE_INFO_MAX,
        }

        public enum CorInfoOptions : ushort
        {
            CORINFO_OPT_INIT_LOCALS = 0x00000010,
            CORINFO_GENERICS_CTXT_FROM_THIS = 0x00000020,
            CORINFO_GENERICS_CTXT_FROM_METHODDESC = 0x00000040,
            CORINFO_GENERICS_CTXT_FROM_METHODTABLE = 0x00000080,

            CORINFO_GENERICS_CTXT_MASK = (CORINFO_GENERICS_CTXT_FROM_THIS | CORINFO_GENERICS_CTXT_FROM_METHODDESC | CORINFO_GENERICS_CTXT_FROM_METHODTABLE),

            CORINFO_GENERICS_CTXT_KEEP_ALIVE = 0x00000100
        }


        public enum CorInfoCallConv
        {
            C = 1,
            DEFAULT = 0,
            EXPLICITTHIS = 64,
            FASTCALL = 4,
            FIELD = 6,
            GENERIC = 16,
            HASTHIS = 32,
            LOCAL_SIG = 7,
            MASK = 15,
            NATIVEVARARG = 11,
            PARAMTYPE = 128,
            PROPERTY = 8,
            STDCALL = 2,
            THISCALL = 3,
            VARARG = 5
        }

        public enum CorInfoType : byte
        {
            BOOL = 2,
            BYREF = 18,
            BYTE = 4,
            CHAR = 3,
            CLASS = 20,
            COUNT = 23,
            DOUBLE = 15,
            FLOAT = 14,
            INT = 8,
            LONG = 10,
            NATIVEINT = 12,
            NATIVEUINT = 13,
            PTR = 17,
            REFANY = 21,
            SHORT = 6,
            STRING = 16,
            UBYTE = 5,
            UINT = 9,
            ULONG = 11,
            UNDEF = 0,
            USHORT = 7,
            VALUECLASS = 19,
            VAR = 22,
            VOID = 1
        }

        public enum CorInfoEHClauseFlags
        {
            CORINFO_EH_CLAUSE_FAULT = 4,
            CORINFO_EH_CLAUSE_FILTER = 1,
            CORINFO_EH_CLAUSE_FINALLY = 2,
            CORINFO_EH_CLAUSE_NONE = 0
        }
    }
}
