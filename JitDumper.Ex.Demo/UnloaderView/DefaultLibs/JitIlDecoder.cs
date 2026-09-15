using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    internal readonly record struct JitIlTokenOperand(int Token, object? Value);

    internal readonly record struct JitIlInstruction(
        int Offset,
        int EndOffset,
        OpCode OpCode,
        object? Operand);

    [HelperClass.SomeElementsInfos("Decodes captured IL for diagnostics.")]
    internal static class JitIlDecoder
    {
        private static readonly FrozenDictionary<short, OpCode> OpCodeMap = BuildOpCodeMap();
        private static readonly SearchValues<char> StringEscapeCharacters =
            SearchValues.Create('\\', '"', '\0', '\a', '\b', '\f', '\n', '\r', '\t', '\v');

        [HelperClass.SomeElementsInfos("Prints raw IL, decoded IL and C#.")]
        public static void LogMethod(JitMethodDescriptor method, in JitMethodContext context, in JitMethodBodyMetadata body)
        {
            StringBuilder output = new(4096);
            output.Append("[JIT] Token=0x").Append(method.MetadataToken.ToString("X8"))
                .Append(" | Method=").Append(GetMethodName(method.Method))
                .Append(" | ILSize=").Append(context.ILCode.Length)
                .Append(" | MaxStack=").Append(body.MaxStack)
                .Append(" | EHCount=").Append(context.EHCount)
                .Append(" | EHSource=").Append(context.ExceptionRegionsFromJit ? "JIT" : "Metadata")
                .Append(" | Options=0x").Append(context.Options.ToString("X8"))
                .Append(" | InitLocals=").Append(body.InitLocals)
                .Append(" | LocalSig=0x").Append(body.LocalSignatureToken.ToString("X8"))
                .Append(" | NativeEntry=0x").Append(StaticMethods.NativeAddressValue(context.NativeEntry).ToString("X"))
                .Append(" | NativeSize=").Append(context.NativeSizeOfCode)
                .AppendLine();

            output.Append("[JIT-RAW] ").AppendLine(FormatBytes(context.ILCode));

            ImmutableArray<JitIlInstruction> instructions = ImmutableArray<JitIlInstruction>.Empty;
            try
            {
                instructions = DecodeInstructions(context.ILCode, method.Method);
                output.AppendLine("[JIT-IL]");
                AppendDecodedInstructions(instructions, output);
            }
            catch (Exception ex)
            {
                output.AppendLine("[JIT-IL]");
                output.Append("<decode failed: ").Append(ex.Message).AppendLine(">");
            }

            if (!instructions.IsDefaultOrEmpty)
            {
                output.AppendLine("[JIT-CS]");
                try
                {
                    JitCSharpRenderer.AppendMethod(method.Method, instructions, in body, output);
                }
                catch (Exception ex)
                {
                    output.Append("// C# reconstruction failed safely: ").Append(ex.Message).AppendLine();
                }
            }

            ImmutableArray<JitExceptionRegion> exceptionRegions = body.ExceptionRegions;
            if (!exceptionRegions.IsDefaultOrEmpty)
            {
                output.AppendLine("[JIT-EH]");
                for (int i = 0; i < exceptionRegions.Length; i++)
                {
                    JitExceptionRegion region = exceptionRegions[i];
                    output.Append(i).Append("  ").Append(region.Kind)
                        .Append(" try=L_").Append(region.TryOffset.ToString("X4"))
                        .Append("..L_").Append((region.TryOffset + region.TryLength).ToString("X4"))
                        .Append(" handler=L_").Append(region.HandlerOffset.ToString("X4"))
                        .Append("..L_").Append((region.HandlerOffset + region.HandlerLength).ToString("X4"));

                    if (region.Kind == JitExceptionRegionKind.Catch)
                        output.Append(" catch=0x").Append(region.CatchTypeToken.ToString("X8"));
                    else if (region.Kind == JitExceptionRegionKind.Filter)
                        output.Append(" filter=L_").Append(region.FilterOffset.ToString("X4"));

                    output.AppendLine();
                }
            }

            ThisStaticClass.Logger.LogInformation("{JitMethodBody}", output.ToString().TrimEnd());
        }

        private static ImmutableArray<JitIlInstruction> DecodeInstructions(ReadOnlySpan<byte> il, MethodBase method)
        {
            ImmutableArray<JitIlInstruction>.Builder instructions = ImmutableArray.CreateBuilder<JitIlInstruction>();
            int offset = 0;
            Module module = method.Module;
            Type[]? typeArguments = method.DeclaringType?.IsGenericType == true ? method.DeclaringType.GetGenericArguments() : null;
            Type[]? methodArguments = method.IsGenericMethod ? method.GetGenericArguments() : null;

            while (offset < il.Length)
            {
                int instructionOffset = offset;
                byte firstByte = ReadByte(il, ref offset);
                short code = firstByte == 0xFE
                    ? (short)(0xFE00 | ReadByte(il, ref offset))
                    : (short)firstByte;

                if (!OpCodeMap.TryGetValue(code, out OpCode opCode))
                    throw new BadImageFormatException($"Unknown IL opcode 0x{unchecked((ushort)code):X4} at L_{instructionOffset:X4}.");

                object? operand = ReadOperand(il, ref offset, instructionOffset, opCode, module, typeArguments, methodArguments);
                instructions.Add(new JitIlInstruction(instructionOffset, offset, opCode, operand));
            }




            return instructions.ToImmutable();
        }

        private static void AppendDecodedInstructions(ImmutableArray<JitIlInstruction> instructions, StringBuilder output)
        {
            for (int i = 0; i < instructions.Length; i++)
            {
                JitIlInstruction instruction = instructions[i];
                output.Append(i).Append("  L_").Append(instruction.Offset.ToString("X4")).Append(": ")
                    .Append(instruction.OpCode.Name?.PadRight(12) ?? "<unknown>     ")
                    .AppendLine(FormatOperand(instruction.Operand));
            }
        }

        internal static string FormatOperand(object? operand)
        {
            return operand switch
            {
                null => string.Empty,
                string text => text,
                sbyte value => value.ToString(),
                byte value => value.ToString(),
                short value => value.ToString(),
                ushort value => value.ToString(),
                int value => value.ToString(),
                long value => value.ToString(),
                float value => value.ToString("R"),
                double value => value.ToString("R"),
                ImmutableArray<int> targets => FormatTargets(targets),
                JitIlTokenOperand tokenOperand => FormatTokenOperand(tokenOperand),
                _ => operand.ToString() ?? string.Empty
            };
        }

        private static object? ReadOperand(
            ReadOnlySpan<byte> il,
            ref int offset,
            int instructionOffset,
            OpCode opCode,
            Module module,
            Type[]? typeArguments,
            Type[]? methodArguments)
        {
            return opCode.OperandType switch
            {
                OperandType.InlineNone => null,
                OperandType.ShortInlineI => (sbyte)ReadByte(il, ref offset),
                OperandType.InlineI => ReadInt32(il, ref offset),
                OperandType.InlineI8 => ReadInt64(il, ref offset),
                OperandType.ShortInlineR => ReadSingle(il, ref offset),
                OperandType.InlineR => ReadDouble(il, ref offset),
                OperandType.ShortInlineVar => (int)ReadByte(il, ref offset),
                OperandType.InlineVar => (int)ReadUInt16(il, ref offset),
                OperandType.ShortInlineBrTarget => ReadShortInlineBranch(il, ref offset),
                OperandType.InlineBrTarget => ReadInlineBranch(il, ref offset),
                OperandType.InlineSwitch => ReadSwitch(il, ref offset),
                OperandType.InlineString => ResolveStringOperand(module, ReadInt32(il, ref offset)),
                OperandType.InlineSig => ResolveSignatureOperand(module, ReadInt32(il, ref offset)),
                OperandType.InlineMethod => ResolveMethodOperand(module, ReadInt32(il, ref offset), typeArguments, methodArguments),
                OperandType.InlineField => ResolveFieldOperand(module, ReadInt32(il, ref offset), typeArguments, methodArguments),
                OperandType.InlineType => ResolveTypeOperand(module, ReadInt32(il, ref offset), typeArguments, methodArguments),
                OperandType.InlineTok => ResolveMemberOperand(module, ReadInt32(il, ref offset), typeArguments, methodArguments),
                _ => $"<unsupported operand {opCode.OperandType} at L_{instructionOffset:X4}>"
            };
        }

        private static int ReadShortInlineBranch(ReadOnlySpan<byte> il, ref int offset)
        {
            sbyte delta = (sbyte)ReadByte(il, ref offset);
            return checked(offset + delta);
        }

        private static int ReadInlineBranch(ReadOnlySpan<byte> il, ref int offset)
        {
            int delta = ReadInt32(il, ref offset);
            return checked(offset + delta);
        }

        private static ImmutableArray<int> ReadSwitch(ReadOnlySpan<byte> il, ref int offset)
        {
            int count = ReadInt32(il, ref offset);
            if (count < 0 || count > (il.Length - offset) / sizeof(int))
                throw new BadImageFormatException("Invalid switch target count.");

            int baseOffset = checked(offset + (count * sizeof(int)));
            ImmutableArray<int>.Builder targets = ImmutableArray.CreateBuilder<int>(count);
            for (int i = 0; i < count; i++)
                targets.Add(checked(baseOffset + ReadInt32(il, ref offset)));

            return targets.MoveToImmutable();
        }

        private static JitIlTokenOperand ResolveStringOperand(Module module, int token)
        {
            try { return new JitIlTokenOperand(token, module.ResolveString(token)); }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static JitIlTokenOperand ResolveSignatureOperand(Module module, int token)
        {
            try
            {
                byte[] signature = module.ResolveSignature(token);
                return new JitIlTokenOperand(token, ImmutableCollectionsMarshal.AsImmutableArray(signature));
            }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static JitIlTokenOperand ResolveMethodOperand(Module module, int token, Type[]? typeArguments, Type[]? methodArguments)
        {
            try { return new JitIlTokenOperand(token, module.ResolveMethod(token, typeArguments, methodArguments)); }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static JitIlTokenOperand ResolveFieldOperand(Module module, int token, Type[]? typeArguments, Type[]? methodArguments)
        {
            try { return new JitIlTokenOperand(token, module.ResolveField(token, typeArguments, methodArguments)); }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static JitIlTokenOperand ResolveTypeOperand(Module module, int token, Type[]? typeArguments, Type[]? methodArguments)
        {
            try { return new JitIlTokenOperand(token, module.ResolveType(token, typeArguments, methodArguments)); }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static JitIlTokenOperand ResolveMemberOperand(Module module, int token, Type[]? typeArguments, Type[]? methodArguments)
        {
            try { return new JitIlTokenOperand(token, module.ResolveMember(token, typeArguments, methodArguments)); }
            catch { return new JitIlTokenOperand(token, null); }
        }

        private static string FormatTokenOperand(JitIlTokenOperand tokenOperand)
        {
            if (tokenOperand.Value is null)
                return FormatToken(tokenOperand.Token);

            return tokenOperand.Value switch
            {
                string text => FormatStringLiteral(text),
                ImmutableArray<byte> signature => FormatBytes(signature.AsSpan()),
                MethodBase method => GetMethodName(method),
                FieldInfo field => $"{field.FieldType} {field.DeclaringType?.FullName ?? "<global>"}::{field.Name}",
                Type type => type.FullName ?? type.ToString(),
                MemberInfo member => member.ToString() ?? FormatToken(tokenOperand.Token),
                _ => tokenOperand.Value.ToString() ?? FormatToken(tokenOperand.Token)
            };
        }

        private static string FormatTargets(ImmutableArray<int> targets)
        {
            StringBuilder text = new(targets.Length * 8);
            for (int i = 0; i < targets.Length; i++)
            {
                if (i != 0)
                    text.Append(", ");
                text.Append("L_").Append(targets[i].ToString("X4"));
            }
            return text.ToString();
        }

        internal static string FormatStringLiteral(string value)
        {
            ReadOnlySpan<char> characters = value.AsSpan();




            if (characters.IndexOfAny(StringEscapeCharacters) < 0 &&
                characters.IndexOfAnyInRange('\u0000', '\u001F') < 0 &&
                characters.IndexOfAnyInRange('\u007F', '\u009F') < 0)
            {
                return "\"" + value + "\"";
            }

            StringBuilder text = new(value.Length + 2);
            text.Append('"');
            foreach (char character in value)
            {
                switch (character)
                {
                    case '\\': text.Append("\\\\"); break;
                    case '"': text.Append("\\\""); break;
                    case '\0': text.Append("\\0"); break;
                    case '\a': text.Append("\\a"); break;
                    case '\b': text.Append("\\b"); break;
                    case '\f': text.Append("\\f"); break;
                    case '\n': text.Append("\\n"); break;
                    case '\r': text.Append("\\r"); break;
                    case '\t': text.Append("\\t"); break;
                    case '\v': text.Append("\\v"); break;
                    default:
                        if (char.IsControl(character))
                            text.Append("\\u").Append(((int)character).ToString("X4"));
                        else
                            text.Append(character);
                        break;
                }
            }
            return text.Append('"').ToString();
        }

        private static string FormatToken(int token) => $"0x{token:X8}";

        private static FrozenDictionary<short, OpCode> BuildOpCodeMap()
        {
            FieldInfo[] fields = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static);
            Dictionary<short, OpCode> opCodes = new(fields.Length);
            foreach (FieldInfo field in fields)
            {
                if (field.GetValue(null) is OpCode opCode)
                    opCodes[opCode.Value] = opCode;
            }

            return opCodes.ToFrozenDictionary();
        }

        internal static string GetMethodName(MethodBase method) => $"{method.DeclaringType?.FullName ?? "<global>"}::{method}";

        internal static string FormatBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.IsEmpty)
                return string.Empty;

            StringBuilder text = new(bytes.Length * 3);
            for (int i = 0; i < bytes.Length; i++)
            {
                if (i != 0)
                    text.Append(' ');
                text.Append(bytes[i].ToString("X2"));
            }
            return text.ToString();
        }

        private static byte ReadByte(ReadOnlySpan<byte> il, ref int offset)
        {
            Ensure(il, offset, 1);
            return il[offset++];
        }

        private static ushort ReadUInt16(ReadOnlySpan<byte> il, ref int offset)
        {
            Ensure(il, offset, sizeof(ushort));
            ushort value = BinaryPrimitives.ReadUInt16LittleEndian(il.Slice(offset, sizeof(ushort)));
            offset += sizeof(ushort);
            return value;
        }

        private static int ReadInt32(ReadOnlySpan<byte> il, ref int offset)
        {
            Ensure(il, offset, sizeof(int));
            int value = BinaryPrimitives.ReadInt32LittleEndian(il.Slice(offset, sizeof(int)));
            offset += sizeof(int);
            return value;
        }

        private static long ReadInt64(ReadOnlySpan<byte> il, ref int offset)
        {
            Ensure(il, offset, sizeof(long));
            long value = BinaryPrimitives.ReadInt64LittleEndian(il.Slice(offset, sizeof(long)));
            offset += sizeof(long);
            return value;
        }

        private static float ReadSingle(ReadOnlySpan<byte> il, ref int offset) => Unsafe.BitCast<int, float>(ReadInt32(il, ref offset));

        private static double ReadDouble(ReadOnlySpan<byte> il, ref int offset) => Unsafe.BitCast<long, double>(ReadInt64(il, ref offset));

        private static void Ensure(ReadOnlySpan<byte> il, int offset, int size)
        {
            if ((uint)offset > (uint)il.Length || size < 0 || offset > il.Length - size)
                throw new BadImageFormatException("Unexpected end of IL stream.");
        }
    }
}
