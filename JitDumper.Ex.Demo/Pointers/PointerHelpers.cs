using HelperClass.Unsafe.JitTools;
using System.Runtime.CompilerServices;

namespace LoaderExDemo
{
    internal static unsafe class PointerHelpers
    {











        internal static List<IntPtr> GetReachableRel32Calls(byte* entry, byte* moduleBase, int moduleSize, bool is64, int maxBlocks, int maxInstructions)
        {
            List<IntPtr> calls = [];

            if (!InsideModule(entry, moduleBase, moduleSize) || maxBlocks <= 0 || maxInstructions <= 0)
            {
                return calls;
            }

            Queue<IntPtr> pending = new();
            HashSet<long> queuedBlocks = [];
            HashSet<long> visitedInstructions = [];

            pending.Enqueue((IntPtr)entry);
            queuedBlocks.Add(((IntPtr)entry).ToInt64());

            int blocks = 0;
            int instructions = 0;
            LdasmWWh ldasm = new();

            while (pending.Count != 0 && blocks < maxBlocks && instructions < maxInstructions)
            {
                byte* p = (byte*)pending.Dequeue().ToPointer();
                blocks++;

                while (InsideModule(p, moduleBase, moduleSize) && instructions < maxInstructions)
                {
                    long address = ((IntPtr)p).ToInt64();
                    if (!visitedInstructions.Add(address))
                        break;

                    uint length;
                    try
                    {
                        length = ldasm.Disassemble(p, is64);
                    }
                    catch
                    {
                        break;
                    }

                    if (length == 0 || length > 15)
                        break;

                    byte* next = p + (int)length;
                    if (next <= p || next > moduleBase + moduleSize)
                        break;

                    instructions++;





                    byte opcode = p[0];


                    if (opcode == 0xE8 && length == 5)
                    {
                        int rel = Unsafe.ReadUnaligned<int>(p + 1);
                        byte* target = next + rel;

                        if (InsideModule(target, moduleBase, moduleSize))
                            calls.Add((IntPtr)p);

                        p = next;
                        continue;
                    }


                    if (opcode == 0xE9 || opcode == 0xEB)
                    {
                        byte* target = opcode == 0xE9
                            ? next + Unsafe.ReadUnaligned<int>(p + 1)
                            : next + Unsafe.ReadUnaligned<sbyte>(p + 1);

                        EnqueueBlock(target, moduleBase, moduleSize, pending, queuedBlocks, maxBlocks);
                        break;
                    }



                    if (opcode >= 0x70 && opcode <= 0x7F)
                    {
                        byte* target = next + Unsafe.ReadUnaligned<sbyte>(p + 1);
                        EnqueueBlock(target, moduleBase, moduleSize, pending, queuedBlocks, maxBlocks);
                        p = next;
                        continue;
                    }


                    if (opcode >= 0xE0 && opcode <= 0xE3)
                    {
                        byte* target = next + Unsafe.ReadUnaligned<sbyte>(p + 1);
                        EnqueueBlock(target, moduleBase, moduleSize, pending, queuedBlocks, maxBlocks);
                        p = next;
                        continue;
                    }



                    if (opcode == 0x0F && length == 6 && p[1] >= 0x80 && p[1] <= 0x8F)
                    {
                        byte* target = next + Unsafe.ReadUnaligned<int>(p + 2);
                        EnqueueBlock(target, moduleBase, moduleSize, pending, queuedBlocks, maxBlocks);
                        p = next;
                        continue;
                    }


                    if (opcode == 0xC3 || opcode == 0xC2 || opcode == 0xCB || opcode == 0xCA || opcode == 0xCC || opcode == 0xF4)
                    {
                        break;
                    }



                    if (opcode == 0xFF && length >= 2)
                    {
                        int group = (p[1] >> 3) & 7;
                        if (group == 4 || group == 5)
                            break;
                    }

                    p = next;
                }
            }

            return calls;
        }

        private static void EnqueueBlock(byte* target, byte* moduleBase, int moduleSize, Queue<IntPtr> pending, HashSet<long> queuedBlocks, int maxBlocks)
        {
            if (!InsideModule(target, moduleBase, moduleSize) || pending.Count >= maxBlocks)
            {
                return;
            }

            IntPtr address = (IntPtr)target;
            long key = address.ToInt64();

            if (queuedBlocks.Add(key))
                pending.Enqueue(address);
        }

        internal static IntPtr ResolveRel32Call(byte* call)
        {
            if (call == null || call[0] != 0xE8)
                return IntPtr.Zero;

            int rel32 = Unsafe.ReadUnaligned<int>(call + 1);
            return (IntPtr)(call + 5 + rel32);
        }

        internal static bool InsideModule(IntPtr address, byte* moduleBase, int moduleSize)
        {
            if (address == IntPtr.Zero || moduleBase == null || moduleSize <= 0)
                return false;

            byte* p = (byte*)address.ToPointer();
            return p >= moduleBase && p < moduleBase + moduleSize;
        }

        internal static bool InsideModule(byte* address, byte* moduleBase, int moduleSize)
        {
            return address != null && moduleBase != null && moduleSize > 0 &&
                   address >= moduleBase && address < moduleBase + moduleSize;
        }

        internal static int ClampScan(byte* start, int requested, byte* moduleBase, int moduleSize)
        {
            if (start == null || moduleBase == null || moduleSize <= 0 || start < moduleBase || start >= moduleBase + moduleSize)
                return 0;

            long remaining = (moduleBase + moduleSize) - start;
            return (int)Math.Min((long)requested, remaining);
        }

        internal static byte* ClampBackward(byte* p, int count, byte* moduleBase)
        {
            long available = p - moduleBase;
            if (available <= 0)
                return moduleBase;

            return p - (int)Math.Min((long)count, available);
        }

        internal static int GetImageSize(byte* moduleBase)
        {
            if (moduleBase == null || moduleBase[0] != 0x4D || moduleBase[1] != 0x5A)
                return 0;

            int e_lfanew = Unsafe.ReadUnaligned<int>(moduleBase + 0x3C);
            if (e_lfanew <= 0)
                return 0;

            byte* nt = moduleBase + e_lfanew;
            if (Unsafe.ReadUnaligned<uint>(nt) != 0x00004550)
                return 0;

            byte* optional = nt + 4 + 20;
            return Unsafe.ReadUnaligned<int>(optional + 0x38);
        }

        internal static bool Is5x(byte value)
        {
            return (value & 0xF0) == 0x50;
        }
    }
}
