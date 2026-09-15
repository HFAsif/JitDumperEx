using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Patches and restores CLR ILOnly branches.")]
    internal static class AllPatches
    {
        private const uint PageExecuteReadWrite = 0x40;


        [HelperClass.SomeElementsInfos("Forces the resolved ILOnly branch path.")]
        public static unsafe byte[] PatchIlOnlyGateUniversal(IntPtr jccAddress)
        {
            if (jccAddress == IntPtr.Zero)
                throw new ArgumentNullException(nameof(jccAddress));

            byte* p = (byte*)jccAddress.ToPointer();
            int length;
            int mode;


            if (p[0] == 0x74)
            {
                length = 2;
                mode = 1;
            }
            else if (p[0] == 0x75)
            {
                length = 2;
                mode = 2;
            }
            else if (p[0] == 0x0F && p[1] == 0x84)
            {
                length = 6;
                mode = 1;
            }
            else if (p[0] == 0x0F && p[1] == 0x85)
            {
                length = 6;
                mode = 2;
            }
            else
            {
                throw new InvalidOperationException(
                    "Unsupported ILOnly Jcc encoding at 0x" +
                    jccAddress.ToInt64().ToString(IntPtr.Size == 8 ? "X16" : "X8") +
                    ": " + p[0].ToString("X2") + " " + p[1].ToString("X2"));
            }

            byte[] original = new ReadOnlySpan<byte>(p, length).ToArray();
            uint oldProtect = 0;
            bool protectionChanged = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(jccAddress, (nuint)length, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException("VirtualProtect failed: " + Marshal.GetLastWin32Error());

                protectionChanged = true;
                Span<byte> code = new(p, length);

                if (length == 2)
                {
                    if (mode == 1)
                    {

                        code[0] = 0xEB;
                    }
                    else
                    {

                        code.Fill(0x90);
                    }
                }
                else if (mode == 1)
                {


                    code[0] = 0x90;
                    code[1] = 0xE9;
                }
                else
                {

                    code.Fill(0x90);
                }

                FlushCode(jccAddress, length);
            }
            finally
            {
                if (protectionChanged)
                    RestoreProtection(jccAddress, (nuint)length, oldProtect);
            }

            return original;
        }

        public static unsafe byte[] PatchNearJneToNops(IntPtr jccAddress)
        {
            if (jccAddress == IntPtr.Zero)
                throw new ArgumentNullException(nameof(jccAddress));

            byte* p = (byte*)jccAddress.ToPointer();
            if (p[0] != 0x0F || p[1] != 0x85)
                throw new InvalidOperationException($"Expected near JNE (0F 85), found {p[0]:X2} {p[1]:X2}");

            byte[] original = new ReadOnlySpan<byte>(p, 6).ToArray();
            uint oldProtect = 0;
            bool protectionChanged = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(jccAddress, (nuint)6, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException("VirtualProtect failed: " + Marshal.GetLastWin32Error());

                protectionChanged = true;
                new Span<byte>(p, 6).Fill(0x90);
                FlushCode(jccAddress, 6);
            }
            finally
            {
                if (protectionChanged)
                    RestoreProtection(jccAddress, (nuint)6, oldProtect);
            }

            return original;
        }

        public static unsafe void RestoreBytes(IntPtr address, byte[] original)
        {
            if (address == IntPtr.Zero || original is not { Length: > 0 })
                return;

            byte* p = (byte*)address.ToPointer();
            uint oldProtect = 0;
            bool protectionChanged = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(address, (nuint)original.Length, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException("VirtualProtect restore failed: " + Marshal.GetLastWin32Error());

                protectionChanged = true;
                original.AsSpan().CopyTo(new Span<byte>(p, original.Length));
                FlushCode(address, original.Length);
            }
            finally
            {
                if (protectionChanged)
                    RestoreProtection(address, (nuint)original.Length, oldProtect);
            }
        }

        public static unsafe byte PatchJeToJmp(IntPtr jccAddress)
        {
            if (jccAddress == IntPtr.Zero)
                throw new ArgumentNullException(nameof(jccAddress));

            byte* p = (byte*)jccAddress.ToPointer();
            if (p[0] != 0x74)
                throw new InvalidOperationException("Expected JE (0x74), found 0x" + p[0].ToString("X2"));

            byte original = p[0];
            uint oldProtect = 0;
            bool protectionChanged = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(jccAddress, (nuint)1, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException("VirtualProtect failed: " + Marshal.GetLastWin32Error());

                protectionChanged = true;
                p[0] = 0xEB;
                FlushCode(jccAddress, 1);
            }
            finally
            {
                if (protectionChanged)
                    RestoreProtection(jccAddress, (nuint)1, oldProtect);
            }

            return original;
        }

        public static unsafe void Restore(IntPtr address, byte originalByte)
        {
            if (address == IntPtr.Zero)
                return;

            byte* p = (byte*)address.ToPointer();
            uint oldProtect = 0;
            bool protectionChanged = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!NativeMethods.VirtualProtect(address, (nuint)1, PageExecuteReadWrite, out oldProtect))
                    throw new InvalidOperationException("VirtualProtect restore failed: " + Marshal.GetLastWin32Error());

                protectionChanged = true;
                p[0] = originalByte;
                FlushCode(address, 1);
            }
            finally
            {
                if (protectionChanged)
                    RestoreProtection(address, (nuint)1, oldProtect);
            }
        }

        private static void FlushCode(IntPtr address, int length)
        {
            if (!NativeMethods.FlushInstructionCache(NativeMethods.GetCurrentProcess(), address, (nuint)length))
                throw new InvalidOperationException("FlushInstructionCache failed. Error=" + Marshal.GetLastWin32Error());
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        private static void RestoreProtection(IntPtr address, nuint length, uint oldProtect)
        {
            if (NativeMethods.VirtualProtect(address, length, oldProtect, out _))
                return;

            try
            {
                ThisStaticClass.Logger.LogCritical(
                    "[PATCH] Failed to restore page protection at 0x{Address:X}. Win32Error={Win32Error}",
                    StaticMethods.NativeAddressValue(address),
                    Marshal.GetLastWin32Error());
            }
            catch
            {
            }
        }
    }
}
