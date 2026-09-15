using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace LoaderExDemo
{
    /// <summary>
    /// Conservative IL-to-C# diagnostic renderer.
    ///
    /// This is intentionally not a source decompiler. It reconstructs expressions and
    /// statements only when the captured IL proves the semantics. Control flow remains
    /// label/goto based when structured C# cannot be established without guessing.
    /// Unsupported instructions are emitted as explicit IL comments rather than being
    /// silently translated into potentially incorrect C#.
    /// </summary>
    [HelperClass.SomeElementsInfos("Conservatively renders IL as readable C#.")]
    internal static class JitCSharpRenderer
    {
        private static readonly FrozenDictionary<Type, string> TypeAliases = BuildTypeAliases();
        private static readonly FrozenSet<string> CSharpKeywords = BuildKeywordSet();

        [HelperClass.SomeElementsInfos("Renders one decoded method to C#.")]
        public static void AppendMethod(
            MethodBase method,
            ImmutableArray<JitIlInstruction> instructions,
            in JitMethodBodyMetadata body,
            StringBuilder output)
        {
            ArgumentNullException.ThrowIfNull(method);
            ArgumentNullException.ThrowIfNull(output);

            StringBuilder methodOutput = new();
            RenderState state = new(method, instructions, in body, methodOutput);
            state.Render();
            output.Append(PolishStructuredControlFlow(methodOutput.ToString()));
        }

        private sealed class RenderState
        {
            private readonly MethodBase _method;
            private readonly ImmutableArray<JitIlInstruction> _instructions;
            private readonly JitMethodBodyMetadata _body;
            private readonly StringBuilder _output;
            private readonly ParameterInfo[] _parameters;
            private readonly Dictionary<int, LocalVariableInfo> _locals;
            private readonly FrozenSet<int> _labels;
            private readonly FrozenSet<int> _elidedTailReturnLocals;
            private readonly FrozenSet<int> _elidedConditionLocals;
            private readonly Dictionary<int, CSharpExpression> _deferredConditionLocals = new();
            private readonly List<CSharpExpression> _stack = new();
            private readonly Dictionary<int, List<FlowState>> _incomingFlows = new();
            private ImmutableArray<BranchDecision> _path = ImmutableArray<BranchDecision>.Empty;
            private bool _reachable = true;
            private Type? _constrainedType;

            public RenderState(
                MethodBase method,
                ImmutableArray<JitIlInstruction> instructions,
                in JitMethodBodyMetadata body,
                StringBuilder output)
            {
                _method = method;
                _instructions = instructions;
                _body = body;
                _output = output;
                _parameters = method.GetParameters();
                _locals = GetLocals(method);
                _labels = BuildLabelSet(instructions, in body);
                _elidedTailReturnLocals = BuildElidedTailReturnLocals(instructions, in body);
                _elidedConditionLocals = BuildElidedConditionLocals(instructions, in body);
            }

            public void Render()
            {
                AppendMethodHeader();
                _output.AppendLine("{");

                AppendMethodMetadataComments();
                AppendLocalDeclarations();

                for (int i = 0; i < _instructions.Length; i++)
                {
                    JitIlInstruction instruction = _instructions[i];
                    EnterLabelIfNeeded(instruction.Offset);
                    if (!_reachable)
                        continue;

                    if (TryRenderProvenTailReturn(i, out int lastConsumedIndex))
                    {
                        i = lastConsumedIndex;
                        continue;
                    }

                    RenderInstruction(in instruction);
                }

                if (_stack.Count != 0)
                {
                    AppendComment($"Evaluation stack retained {_stack.Count} value(s) at end of method; exact high-level reconstruction is incomplete.");
                    _stack.Clear();
                }

                _output.AppendLine("}");
            }

            private void AppendMethodHeader()
            {
                bool isStaticConstructor = _method is ConstructorInfo staticConstructor && staticConstructor.IsStatic;
                if (!isStaticConstructor)
                    _output.Append(FormatVisibility(_method));

                if (_method.IsStatic)
                {
                    if (!isStaticConstructor)
                        _output.Append(' ');
                    _output.Append("static");
                }

                if (_method is MethodInfo methodInfo)
                {
                    if (methodInfo.IsAbstract)
                        _output.Append(" abstract");
                    else if (methodInfo.IsVirtual)
                    {
                        bool newSlot = (methodInfo.Attributes & MethodAttributes.NewSlot) != 0;
                        if (!newSlot)
                        {
                            if (methodInfo.IsFinal)
                                _output.Append(" sealed");
                            _output.Append(" override");
                        }
                        else if (!methodInfo.IsFinal)
                        {
                            _output.Append(" virtual");
                        }
                    }

                    _output.Append(' ');
                    if (methodInfo.ReturnType.IsByRef)
                        _output.Append("ref ");
                    _output.Append(FormatType(methodInfo.ReturnType)).Append(' ');
                    _output.Append(EscapeIdentifier(methodInfo.Name));
                    AppendGenericMethodArguments(methodInfo);
                }
                else if (_method is ConstructorInfo constructor)
                {
                    _output.Append(' ');
                    _output.Append(FormatSimpleTypeName(constructor.DeclaringType ?? typeof(object)));
                }
                else
                {
                    _output.Append(" void ").Append(EscapeIdentifier(_method.Name));
                }

                AppendParameters();
            }

            private void AppendParameters()
            {
                _output.Append('(');
                for (int i = 0; i < _parameters.Length; i++)
                {
                    if (i != 0)
                        _output.Append(", ");

                    ParameterInfo parameter = _parameters[i];
                    Type parameterType = parameter.ParameterType;
                    if (parameter.IsOut)
                        _output.Append("out ");
                    else if (parameterType.IsByRef && parameter.IsIn)
                        _output.Append("in ");
                    else if (parameterType.IsByRef)
                        _output.Append("ref ");

                    if (parameterType.IsByRef)
                        parameterType = parameterType.GetElementType() ?? parameterType;

                    _output.Append(FormatType(parameterType)).Append(' ')
                        .Append(EscapeIdentifier(GetParameterName(parameter, i)));
                }
                _output.AppendLine(")");
            }

            private void AppendGenericMethodArguments(MethodInfo methodInfo)
            {
                if (!methodInfo.IsGenericMethod)
                    return;

                Type[] genericArguments = methodInfo.GetGenericArguments();
                if (genericArguments.Length == 0)
                    return;

                _output.Append('<');
                for (int i = 0; i < genericArguments.Length; i++)
                {
                    if (i != 0)
                        _output.Append(", ");
                    _output.Append(FormatType(genericArguments[i]));
                }
                _output.Append('>');
            }

            private void AppendMethodMetadataComments()
            {
                if (_body.ExceptionRegions.Length != 0)
                    AppendComment("Exception regions are preserved separately in [JIT-EH]; this renderer keeps conservative label/goto control flow.");

                if (_body.LocalSignatureToken != 0 && _locals.Count == 0)
                    AppendComment($"Local signature 0x{_body.LocalSignatureToken:X8} exists but runtime local types were unavailable.");
            }

            private void AppendLocalDeclarations()
            {
                if (_locals.Count == 0)
                    return;

                List<int> indexes = new(_locals.Keys);
                indexes.Sort();
                bool emittedAny = false;

                foreach (int index in indexes)
                {
                    if (_elidedTailReturnLocals.Contains(index) || _elidedConditionLocals.Contains(index))
                        continue;

                    LocalVariableInfo local = _locals[index];
                    _output.Append("    ");
                    if (local.IsPinned)
                        _output.Append("/* pinned */ ");
                    _output.Append(FormatType(local.LocalType)).Append(" V_").Append(index).AppendLine(";");
                    emittedAny = true;
                }

                if (emittedAny)
                    _output.AppendLine();
            }

            private void EnterLabelIfNeeded(int offset)
            {
                if (!_labels.Contains(offset))
                    return;

                List<FlowState> flows = new();
                if (_reachable)
                    flows.Add(CaptureFlowState());

                if (_incomingFlows.TryGetValue(offset, out List<FlowState>? incoming))
                    flows.AddRange(incoming);

                if (flows.Count != 0)
                    RestoreMergedFlow(offset, flows);
                else
                {
                    _reachable = false;
                    _stack.Clear();
                    _path = ImmutableArray<BranchDecision>.Empty;
                }

                _output.Append("    IL_").Append(offset.ToString("X4")).AppendLine(":");
            }

            private FlowState CaptureFlowState() =>
                new(_stack.ToImmutableArray(), _path);

            private void RecordIncomingFlow(int targetOffset, ImmutableArray<BranchDecision> path)
            {
                if (!_incomingFlows.TryGetValue(targetOffset, out List<FlowState>? flows))
                {
                    flows = new List<FlowState>();
                    _incomingFlows.Add(targetOffset, flows);
                }

                flows.Add(new FlowState(_stack.ToImmutableArray(), path));
            }

            private void RestoreMergedFlow(int offset, List<FlowState> flows)
            {
                _reachable = true;
                _stack.Clear();

                if (flows.Count == 1)
                {
                    _stack.AddRange(flows[0].Stack);
                    _path = flows[0].Path;
                    return;
                }

                int stackDepth = flows[0].Stack.Length;
                for (int i = 1; i < flows.Count; i++)
                {
                    if (flows[i].Stack.Length != stackDepth)
                    {
                        AppendComment($"IL_{offset:X4} merge has incompatible evaluation-stack depths; stack values were discarded rather than guessed.");
                        _path = CommonPathPrefix(flows);
                        return;
                    }
                }

                if (TryGetSiblingBranchMerge(flows, out BranchDecision decision, out int trueIndex, out int falseIndex, out ImmutableArray<BranchDecision> commonPath))
                {
                    for (int slot = 0; slot < stackDepth; slot++)
                    {
                        CSharpExpression whenTrue = flows[trueIndex].Stack[slot];
                        CSharpExpression whenFalse = flows[falseIndex].Stack[slot];
                        _stack.Add(MergeExpressions(decision.Test, whenTrue, whenFalse));
                    }
                    _path = commonPath;
                    return;
                }

                for (int slot = 0; slot < stackDepth; slot++)
                {
                    CSharpExpression first = flows[0].Stack[slot];
                    bool identical = true;
                    for (int i = 1; i < flows.Count; i++)
                    {
                        if (!Equivalent(first, flows[i].Stack[slot]))
                        {
                            identical = false;
                            break;
                        }
                    }

                    if (!identical)
                    {
                        AppendComment($"IL_{offset:X4} merge has {flows.Count} distinct stack expressions; stack values were discarded rather than fabricated.");
                        _stack.Clear();
                        _path = CommonPathPrefix(flows);
                        return;
                    }
                    _stack.Add(first);
                }

                _path = CommonPathPrefix(flows);
            }

            private static bool TryGetSiblingBranchMerge(
                List<FlowState> flows,
                out BranchDecision decision,
                out int trueIndex,
                out int falseIndex,
                out ImmutableArray<BranchDecision> commonPath)
            {
                decision = default;
                trueIndex = -1;
                falseIndex = -1;
                commonPath = ImmutableArray<BranchDecision>.Empty;

                if (flows.Count != 2 || flows[0].Path.Length == 0 || flows[1].Path.Length == 0 || flows[0].Path.Length != flows[1].Path.Length)
                    return false;

                int last = flows[0].Path.Length - 1;
                for (int i = 0; i < last; i++)
                {
                    if (!flows[0].Path[i].Equals(flows[1].Path[i]))
                        return false;
                }

                BranchDecision left = flows[0].Path[last];
                BranchDecision right = flows[1].Path[last];
                if (left.BranchOffset != right.BranchOffset || !string.Equals(left.Test, right.Test, StringComparison.Ordinal) || left.Taken == right.Taken)
                    return false;

                decision = left;
                trueIndex = left.Taken ? 0 : 1;
                falseIndex = left.Taken ? 1 : 0;
                ImmutableArray<BranchDecision>.Builder commonBuilder = ImmutableArray.CreateBuilder<BranchDecision>(last);
                for (int i = 0; i < last; i++)
                    commonBuilder.Add(flows[0].Path[i]);
                commonPath = commonBuilder.MoveToImmutable();
                return true;
            }

            private static ImmutableArray<BranchDecision> CommonPathPrefix(List<FlowState> flows)
            {
                if (flows.Count == 0)
                    return ImmutableArray<BranchDecision>.Empty;

                int length = flows[0].Path.Length;
                for (int i = 1; i < flows.Count; i++)
                    length = Math.Min(length, flows[i].Path.Length);

                int common = 0;
                for (; common < length; common++)
                {
                    BranchDecision candidate = flows[0].Path[common];
                    bool allMatch = true;
                    for (int i = 1; i < flows.Count; i++)
                    {
                        if (!candidate.Equals(flows[i].Path[common]))
                        {
                            allMatch = false;
                            break;
                        }
                    }
                    if (!allMatch)
                        break;
                }

                ImmutableArray<BranchDecision>.Builder builder = ImmutableArray.CreateBuilder<BranchDecision>(common);
                for (int i = 0; i < common; i++)
                    builder.Add(flows[0].Path[i]);
                return builder.MoveToImmutable();
            }

            private static CSharpExpression MergeExpressions(string test, CSharpExpression whenTrue, CSharpExpression whenFalse)
            {
                if (Equivalent(whenTrue, whenFalse))
                    return whenTrue;

                Type? type = DetermineMergeType(whenTrue, whenFalse);
                string trueText = FormatExpressionForExpectedType(whenTrue, type);
                string falseText = FormatExpressionForExpectedType(whenFalse, type);

                if (type == typeof(bool))
                {
                    string negatedTest = NegateBooleanTest(test);
                    if (string.Equals(trueText, "false", StringComparison.Ordinal))
                        return new CSharpExpression($"({negatedTest} && {falseText})", typeof(bool));
                    if (string.Equals(falseText, "false", StringComparison.Ordinal))
                        return new CSharpExpression($"({test} && {trueText})", typeof(bool));
                    if (string.Equals(trueText, "true", StringComparison.Ordinal))
                        return new CSharpExpression($"({test} || {falseText})", typeof(bool));
                    if (string.Equals(falseText, "true", StringComparison.Ordinal))
                        return new CSharpExpression($"({negatedTest} || {trueText})", typeof(bool));
                }

                return new CSharpExpression($"({test} ? {trueText} : {falseText})", type);
            }

            private static string NegateBooleanTest(string test)
            {
                string value = test.Trim();
                if (value.Length >= 4 && value.StartsWith("!(", StringComparison.Ordinal) && value.EndsWith(")", StringComparison.Ordinal))
                    return value.Substring(2, value.Length - 3);
                if (value.Length >= 2 && value[0] == '!' && value[1] != '=')
                    return value.Substring(1);
                return "!(" + value + ")";
            }

            private static bool Equivalent(CSharpExpression left, CSharpExpression right) =>
                string.Equals(left.Text, right.Text, StringComparison.Ordinal) && left.Type == right.Type && left.IsAddress == right.IsAddress;

            private void RenderInstruction(in JitIlInstruction instruction)
            {
                OpCode opCode = instruction.OpCode;

                if (Is(opCode, OpCodes.Nop))
                    return;

                if (Is(opCode, OpCodes.Break))
                {
                    AppendStatement("System.Diagnostics.Debugger.Break();");
                    return;
                }

                if (TryRenderArgumentInstruction(in instruction) ||
                    TryRenderLocalInstruction(in instruction) ||
                    TryRenderConstantInstruction(in instruction) ||
                    TryRenderStackInstruction(in instruction) ||
                    TryRenderArithmeticInstruction(in instruction) ||
                    TryRenderBranchInstruction(in instruction) ||
                    TryRenderCallInstruction(in instruction) ||
                    TryRenderFieldInstruction(in instruction) ||
                    TryRenderArrayInstruction(in instruction) ||
                    TryRenderTypeInstruction(in instruction) ||
                    TryRenderIndirectInstruction(in instruction) ||
                    TryRenderTerminalInstruction(in instruction) ||
                    TryRenderPrefixInstruction(in instruction))
                {
                    return;
                }

                EmitUnsupported(in instruction);
            }

            private bool TryRenderProvenTailReturn(int instructionIndex, out int lastConsumedIndex)
            {
                lastConsumedIndex = instructionIndex;
                if (_body.ExceptionRegions.Length != 0 || instructionIndex + 3 >= _instructions.Length)
                    return false;

                JitIlInstruction store = _instructions[instructionIndex];
                if (!TryGetStoredLocalIndexCore(in store, out int localIndex))
                    return false;

                JitIlInstruction branch = _instructions[instructionIndex + 1];
                if (!Is(branch.OpCode, OpCodes.Br) && !Is(branch.OpCode, OpCodes.Br_S))
                    return false;

                JitIlInstruction load = _instructions[instructionIndex + 2];
                JitIlInstruction ret = _instructions[instructionIndex + 3];
                if (GetBranchTarget(in branch) != load.Offset ||
                    !TryGetLoadedLocalIndexCore(in load, out int loadedLocal) || loadedLocal != localIndex ||
                    !Is(ret.OpCode, OpCodes.Ret) ||
                    CountBranchReferences(load.Offset) != 1 ||
                    CountLocalReferences(localIndex) != 2 ||
                    _method is not MethodInfo methodInfo || methodInfo.ReturnType == typeof(void))
                {
                    return false;
                }

                CSharpExpression value = Pop();
                AppendStatement("return " + FormatExpressionForExpectedType(value, methodInfo.ReturnType) + ";");
                _stack.Clear();
                _reachable = false;
                lastConsumedIndex = instructionIndex + 3;
                return true;
            }

            private int CountBranchReferences(int targetOffset)
            {
                int count = 0;
                for (int i = 0; i < _instructions.Length; i++)
                {
                    JitIlInstruction instruction = _instructions[i];
                    if (IsBranchOperand(instruction.OpCode) && instruction.Operand is int branchTarget && branchTarget == targetOffset)
                    {
                        count++;
                    }
                    else if (Is(instruction.OpCode, OpCodes.Switch) && instruction.Operand is ImmutableArray<int> switchTargets)
                    {
                        for (int j = 0; j < switchTargets.Length; j++)
                        {
                            if (switchTargets[j] == targetOffset)
                                count++;
                        }
                    }
                }
                return count;
            }

            private int CountLocalReferences(int localIndex)
            {
                int count = 0;
                for (int i = 0; i < _instructions.Length; i++)
                {
                    JitIlInstruction instruction = _instructions[i];
                    if (TryGetReferencedLocalIndexCore(in instruction, out int referenced) && referenced == localIndex)
                        count++;
                }
                return count;
            }

            private bool TryRenderArgumentInstruction(in JitIlInstruction instruction)
            {
                int argumentIndex;
                if (Is(instruction.OpCode, OpCodes.Ldarg_0)) argumentIndex = 0;
                else if (Is(instruction.OpCode, OpCodes.Ldarg_1)) argumentIndex = 1;
                else if (Is(instruction.OpCode, OpCodes.Ldarg_2)) argumentIndex = 2;
                else if (Is(instruction.OpCode, OpCodes.Ldarg_3)) argumentIndex = 3;
                else if (Is(instruction.OpCode, OpCodes.Ldarg) || Is(instruction.OpCode, OpCodes.Ldarg_S)) argumentIndex = GetVariableIndex(in instruction);
                else if (Is(instruction.OpCode, OpCodes.Ldarga) || Is(instruction.OpCode, OpCodes.Ldarga_S))
                {
                    argumentIndex = GetVariableIndex(in instruction);
                    CSharpExpression argument = GetArgumentExpression(argumentIndex);
                    Push(argument.AsAddress());
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Starg) || Is(instruction.OpCode, OpCodes.Starg_S))
                {
                    argumentIndex = GetVariableIndex(in instruction);
                    CSharpExpression value = Pop();
                    CSharpExpression argument = GetArgumentExpression(argumentIndex);
                    if (argument.Text == "this")
                        AppendComment($"IL_{instruction.Offset:X4}: starg attempts to replace the instance argument; emitted without inventing C# semantics. Value={value.Text}");
                    else
                        AppendStatement($"{argument.Text} = {value.Text};");
                    return true;
                }
                else
                {
                    return false;
                }

                Push(GetArgumentExpression(argumentIndex));
                return true;
            }

            private bool TryRenderLocalInstruction(in JitIlInstruction instruction)
            {
                int localIndex;
                if (Is(instruction.OpCode, OpCodes.Ldloc_0)) localIndex = 0;
                else if (Is(instruction.OpCode, OpCodes.Ldloc_1)) localIndex = 1;
                else if (Is(instruction.OpCode, OpCodes.Ldloc_2)) localIndex = 2;
                else if (Is(instruction.OpCode, OpCodes.Ldloc_3)) localIndex = 3;
                else if (Is(instruction.OpCode, OpCodes.Stloc_0))
                {
                    StoreLocal(0);
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Stloc_1))
                {
                    StoreLocal(1);
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Stloc_2))
                {
                    StoreLocal(2);
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Stloc_3))
                {
                    StoreLocal(3);
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Ldloc) || Is(instruction.OpCode, OpCodes.Ldloc_S))
                {
                    localIndex = GetVariableIndex(in instruction);
                }
                else if (Is(instruction.OpCode, OpCodes.Stloc) || Is(instruction.OpCode, OpCodes.Stloc_S))
                {
                    StoreLocal(GetVariableIndex(in instruction));
                    return true;
                }
                else if (Is(instruction.OpCode, OpCodes.Ldloca) || Is(instruction.OpCode, OpCodes.Ldloca_S))
                {
                    localIndex = GetVariableIndex(in instruction);
                    Push(GetLocalExpression(localIndex).AsAddress());
                    return true;
                }
                else
                {
                    return false;
                }

                if (_elidedConditionLocals.Contains(localIndex) && _deferredConditionLocals.TryGetValue(localIndex, out CSharpExpression deferred))
                {
                    _deferredConditionLocals.Remove(localIndex);
                    Push(deferred);
                }
                else
                {
                    Push(GetLocalExpression(localIndex));
                }
                return true;
            }

            private bool TryRenderConstantInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Ldnull))
                {
                    Push(new CSharpExpression("null", null));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldstr))
                {
                    if (TryGetResolvedTokenValue(in instruction, out object? value) && value is string text)
                        Push(new CSharpExpression(JitIlDecoder.FormatStringLiteral(text), typeof(string)));
                    else
                        PushUnknownTokenExpression(in instruction, "string");
                    return true;
                }

                int? int32 = GetInt32Constant(in instruction);
                if (int32.HasValue)
                {
                    Push(new CSharpExpression(int32.Value.ToString(CultureInfo.InvariantCulture), typeof(int)));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldc_I8) && instruction.Operand is long int64)
                {
                    Push(new CSharpExpression(int64.ToString(CultureInfo.InvariantCulture) + "L", typeof(long)));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldc_R4) && instruction.Operand is float single)
                {
                    Push(new CSharpExpression(FormatSingle(single), typeof(float)));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldc_R8) && instruction.Operand is double dbl)
                {
                    Push(new CSharpExpression(FormatDouble(dbl), typeof(double)));
                    return true;
                }

                return false;
            }

            private bool TryRenderStackInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Dup))
                {
                    Push(Peek());
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Pop))
                {
                    CSharpExpression discarded = Pop();
                    AppendStatement($"_ = {discarded.Text};");
                    return true;
                }

                return false;
            }

            private bool TryRenderArithmeticInstruction(in JitIlInstruction instruction)
            {
                string? binaryOperator = GetBinaryOperator(instruction.OpCode);
                if (binaryOperator is not null)
                {
                    CSharpExpression right = Pop();
                    CSharpExpression left = Pop();
                    string expression = $"({left.Text} {binaryOperator} {right.Text})";

                    if (IsOverflowChecked(instruction.OpCode))
                        expression = $"checked({expression})";
                    else if (IsUnsignedArithmetic(instruction.OpCode))
                        expression = $"/* unsigned */ {expression}";

                    Push(new CSharpExpression(expression, left.Type ?? right.Type));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Neg))
                {
                    CSharpExpression value = Pop();
                    Push(new CSharpExpression($"(-{value.Text})", value.Type));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Not))
                {
                    CSharpExpression value = Pop();
                    Push(new CSharpExpression($"(~{value.Text})", value.Type));
                    return true;
                }

                string? comparison = GetComparisonOperator(instruction.OpCode);
                if (comparison is not null)
                {
                    CSharpExpression right = Pop();
                    CSharpExpression left = Pop();
                    Push(new CSharpExpression(FormatComparisonExpression(instruction.OpCode, left, right), typeof(bool)));
                    return true;
                }

                Type? conversionType = GetConversionType(instruction.OpCode);
                if (conversionType is not null)
                {
                    CSharpExpression value = Pop();
                    string expression = $"(({FormatType(conversionType)})({value.Text}))";
                    if (IsOverflowCheckedConversion(instruction.OpCode))
                        expression = $"checked({expression})";
                    if (IsUnsignedConversion(instruction.OpCode))
                        expression = $"/* unsigned source */ {expression}";
                    Push(new CSharpExpression(expression, conversionType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ckfinite))
                {
                    CSharpExpression value = Pop();
                    Push(new CSharpExpression($"/* ckfinite */ {value.Text}", value.Type));
                    return true;
                }

                return false;
            }

            private bool TryRenderBranchInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Br) || Is(instruction.OpCode, OpCodes.Br_S) ||
                    Is(instruction.OpCode, OpCodes.Leave) || Is(instruction.OpCode, OpCodes.Leave_S))
                {
                    int target = GetBranchTarget(in instruction);
                    if (Is(instruction.OpCode, OpCodes.Leave) || Is(instruction.OpCode, OpCodes.Leave_S))
                        _stack.Clear();

                    RecordIncomingFlow(target, _path);
                    AppendStatement($"goto {FormatLabel(target)};");
                    _reachable = false;
                    _stack.Clear();
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Brtrue) || Is(instruction.OpCode, OpCodes.Brtrue_S) ||
                    Is(instruction.OpCode, OpCodes.Brfalse) || Is(instruction.OpCode, OpCodes.Brfalse_S))
                {
                    bool branchWhenTrue = Is(instruction.OpCode, OpCodes.Brtrue) || Is(instruction.OpCode, OpCodes.Brtrue_S);
                    CSharpExpression condition = Pop();
                    string test = FormatTruthTest(condition, branchWhenTrue);
                    int target = GetBranchTarget(in instruction);
                    BranchDecision taken = new(instruction.Offset, test, true);
                    BranchDecision fallthrough = new(instruction.Offset, test, false);
                    RecordIncomingFlow(target, _path.Add(taken));
                    _path = _path.Add(fallthrough);
                    AppendStatement($"if ({test}) goto {FormatLabel(target)};");
                    return true;
                }

                string? branchComparison = GetBranchComparisonOperator(instruction.OpCode);
                if (branchComparison is not null)
                {
                    CSharpExpression right = Pop();
                    CSharpExpression left = Pop();
                    string test = FormatBranchComparisonExpression(instruction.OpCode, left, right);
                    int target = GetBranchTarget(in instruction);
                    BranchDecision taken = new(instruction.Offset, test, true);
                    BranchDecision fallthrough = new(instruction.Offset, test, false);
                    RecordIncomingFlow(target, _path.Add(taken));
                    _path = _path.Add(fallthrough);
                    AppendStatement($"if ({test}) goto {FormatLabel(target)};");
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Switch) && instruction.Operand is ImmutableArray<int> targets)
                {
                    CSharpExpression selector = Pop();
                    _output.Append("        switch (").Append(selector.Text).AppendLine(")");
                    _output.AppendLine("        {");
                    for (int i = 0; i < targets.Length; i++)
                    {
                        string test = $"{selector.Text} == {i.ToString(CultureInfo.InvariantCulture)}";
                        RecordIncomingFlow(targets[i], _path.Add(new BranchDecision(instruction.Offset, test, true)));
                        _output.Append("            case ").Append(i).Append(": goto ").Append(FormatLabel(targets[i])).AppendLine(";");
                    }
                    _output.AppendLine("        }");
                    return true;
                }

                return false;
            }

            private bool TryRenderCallInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Newobj))
                {
                    if (!TryGetResolvedTokenValue(in instruction, out object? value) || value is not ConstructorInfo constructor)
                    {
                        EmitUnsupported(in instruction);
                        return true;
                    }

                    ParameterInfo[] parameters = constructor.GetParameters();
                    CSharpExpression[] arguments = PopArguments(parameters);
                    if (TryFormatDelegateConstruction(constructor, arguments, out string? delegateConstruction))
                    {
                        Push(new CSharpExpression(delegateConstruction, constructor.DeclaringType));
                        return true;
                    }

                    string invocation = $"new {FormatType(constructor.DeclaringType ?? typeof(object))}({FormatArguments(arguments, parameters)})";
                    Push(new CSharpExpression(invocation, constructor.DeclaringType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Call) || Is(instruction.OpCode, OpCodes.Callvirt))
                {
                    if (!TryGetResolvedTokenValue(in instruction, out object? value) || value is not MethodBase calledMethod)
                    {
                        EmitUnsupported(in instruction);
                        return true;
                    }

                    ParameterInfo[] parameters = calledMethod.GetParameters();
                    CSharpExpression[] arguments = PopArguments(parameters);
                    CSharpExpression? instance = null;
                    if (!calledMethod.IsStatic)
                        instance = Pop();

                    if (calledMethod is ConstructorInfo constructor)
                    {
                        string owner = instance?.Text ?? "<missing-instance>";
                        if (!IsImplicitParameterlessBaseConstructorCall(constructor, instance, arguments))
                        {
                            AppendComment($"IL_{instruction.Offset:X4}: constructor call {FormatType(constructor.DeclaringType ?? typeof(object))}::.ctor({FormatArguments(arguments, parameters)}) on {owner}.");
                        }
                        _constrainedType = null;
                        return true;
                    }

                    MethodInfo methodInfo = (MethodInfo)calledMethod;
                    if (TryRenderSpecialNameInvocation(methodInfo, instance, arguments, out CSharpExpression? specialResult))
                    {
                        _constrainedType = null;
                        if (specialResult.HasValue)
                            Push(specialResult.Value);
                        return true;
                    }

                    bool useBaseTarget = ShouldRenderBaseCall(instruction.OpCode, methodInfo, instance);
                    string invocation = FormatMethodInvocation(methodInfo, instance, arguments, parameters, useBaseTarget);
                    _constrainedType = null;

                    if (methodInfo.ReturnType == typeof(void))
                        AppendStatement(invocation + ";");
                    else
                        Push(new CSharpExpression(invocation, methodInfo.ReturnType));

                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Calli))
                {
                    AppendComment($"IL_{instruction.Offset:X4}: calli {JitIlDecoder.FormatOperand(instruction.Operand)}; indirect signature invocation is preserved as IL rather than guessed C#.");
                    ApplyUnknownStackBehaviour(instruction.OpCode);
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldftn) || Is(instruction.OpCode, OpCodes.Ldvirtftn))
                {
                    CSharpExpression? instance = Is(instruction.OpCode, OpCodes.Ldvirtftn) ? Pop() : null;
                    if (TryGetResolvedTokenValue(in instruction, out object? value) && value is MethodBase target)
                    {
                        string targetName = instance is null
                            ? FormatMethodReference(target)
                            : ParenthesizeTarget(instance.Value.Text) + "." + EscapeIdentifier(target.Name);
                        Push(new CSharpExpression(
                            $"/* ldftn {targetName} */ default(nint)",
                            typeof(IntPtr),
                            FunctionPointerTarget: target,
                            FunctionPointerInstance: instance?.Text));
                    }
                    else
                    {
                        PushUnknownTokenExpression(in instruction, "function pointer");
                    }
                    return true;
                }

                return false;
            }

            private bool IsImplicitParameterlessBaseConstructorCall(
                ConstructorInfo constructor,
                CSharpExpression? instance,
                CSharpExpression[] arguments)
            {
                if (!instance.HasValue || instance.Value.Text != "this" || arguments.Length != 0)
                    return false;

                Type? currentType = _method.DeclaringType;
                Type? baseType = currentType?.BaseType;
                return baseType is not null && constructor.DeclaringType == baseType;
            }

            private bool TryRenderFieldInstruction(in JitIlInstruction instruction)
            {
                if (!IsFieldInstruction(instruction.OpCode))
                    return false;

                if (!TryGetResolvedTokenValue(in instruction, out object? value) || value is not FieldInfo field)
                {
                    EmitUnsupported(in instruction);
                    return true;
                }

                string fieldName = EscapeIdentifier(field.Name);
                string staticTarget = FormatType(field.DeclaringType ?? typeof(object)) + "." + fieldName;

                if (Is(instruction.OpCode, OpCodes.Ldsfld))
                {
                    Push(new CSharpExpression(staticTarget, field.FieldType, staticTarget));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldsflda))
                {
                    Push(new CSharpExpression(staticTarget, field.FieldType, staticTarget, true));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Stsfld))
                {
                    CSharpExpression valueExpression = Pop();
                    AppendStatement($"{staticTarget} = {valueExpression.Text};");
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldfld) || Is(instruction.OpCode, OpCodes.Ldflda))
                {
                    CSharpExpression target = Pop();
                    string member = $"{ParenthesizeTarget(target.Text)}.{fieldName}";
                    bool address = Is(instruction.OpCode, OpCodes.Ldflda);
                    Push(new CSharpExpression(member, field.FieldType, member, address));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Stfld))
                {
                    CSharpExpression fieldValue = Pop();
                    CSharpExpression target = Pop();
                    AppendStatement($"{ParenthesizeTarget(target.Text)}.{fieldName} = {fieldValue.Text};");
                    return true;
                }

                return false;
            }

            private bool TryRenderArrayInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Newarr))
                {
                    CSharpExpression length = Pop();
                    Type elementType = GetResolvedType(in instruction) ?? typeof(object);
                    Type? arrayType = null;
                    try { arrayType = elementType.MakeArrayType(); } catch { }
                    Push(new CSharpExpression($"new {FormatType(elementType)}[{length.Text}]", arrayType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldlen))
                {
                    CSharpExpression array = Pop();
                    Push(new CSharpExpression($"{ParenthesizeTarget(array.Text)}.Length", typeof(int)));
                    return true;
                }

                if (IsLoadElement(instruction.OpCode))
                {
                    CSharpExpression index = Pop();
                    CSharpExpression array = Pop();
                    Type? elementType = GetElementTypeFromLoad(in instruction, array.Type);
                    string access = $"{ParenthesizeTarget(array.Text)}[{index.Text}]";
                    Push(new CSharpExpression(access, elementType, access));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldelema))
                {
                    CSharpExpression index = Pop();
                    CSharpExpression array = Pop();
                    Type? elementType = GetResolvedType(in instruction) ?? array.Type?.GetElementType();
                    string access = $"{ParenthesizeTarget(array.Text)}[{index.Text}]";
                    Push(new CSharpExpression(access, elementType, access, true));
                    return true;
                }

                if (IsStoreElement(instruction.OpCode))
                {
                    CSharpExpression value = Pop();
                    CSharpExpression index = Pop();
                    CSharpExpression array = Pop();
                    AppendStatement($"{ParenthesizeTarget(array.Text)}[{index.Text}] = {value.Text};");
                    return true;
                }

                return false;
            }

            private bool TryRenderTypeInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Castclass))
                {
                    CSharpExpression value = Pop();
                    Type targetType = GetResolvedType(in instruction) ?? typeof(object);
                    Push(new CSharpExpression($"(({FormatType(targetType)})({value.Text}))", targetType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Isinst))
                {
                    CSharpExpression value = Pop();
                    Type? targetType = GetResolvedType(in instruction);
                    if (targetType is not null && !targetType.IsValueType)
                        Push(new CSharpExpression($"({value.Text} as {FormatType(targetType)})", targetType));
                    else
                        Push(new CSharpExpression($"/* isinst {FormatResolvedTypeOrToken(in instruction)} */ ({value.Text})", targetType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Box))
                {
                    CSharpExpression value = Pop();
                    Type? boxedType = GetResolvedType(in instruction);
                    string typeComment = boxedType is null ? FormatResolvedTypeOrToken(in instruction) : FormatType(boxedType);
                    Push(new CSharpExpression($"/* box {typeComment} */ (object)({value.Text})", typeof(object)));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Unbox_Any))
                {
                    CSharpExpression value = Pop();
                    Type targetType = GetResolvedType(in instruction) ?? typeof(object);
                    Push(new CSharpExpression($"(({FormatType(targetType)})({value.Text}))", targetType));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Unbox))
                {
                    CSharpExpression value = Pop();
                    Type? targetType = GetResolvedType(in instruction);
                    string typeName = targetType is null ? FormatResolvedTypeOrToken(in instruction) : FormatType(targetType);
                    Push(new CSharpExpression($"/* unbox address {typeName} */ ({value.Text})", targetType, null, true));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Sizeof))
                {
                    Type? targetType = GetResolvedType(in instruction);
                    if (targetType is not null)
                        Push(new CSharpExpression($"sizeof({FormatType(targetType)})", typeof(int)));
                    else
                        PushUnknownTokenExpression(in instruction, "sizeof");
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Ldtoken))
                {
                    if (TryGetResolvedTokenValue(in instruction, out object? tokenValue))
                    {
                        if (tokenValue is Type type)
                            Push(new CSharpExpression($"typeof({FormatType(type)}).TypeHandle", typeof(RuntimeTypeHandle)));
                        else if (tokenValue is FieldInfo field)
                            Push(new CSharpExpression($"/* ldtoken {FormatFieldReference(field)} */ default(RuntimeFieldHandle)", typeof(RuntimeFieldHandle)));
                        else if (tokenValue is MethodBase method)
                            Push(new CSharpExpression($"/* ldtoken {FormatMethodReference(method)} */ default(RuntimeMethodHandle)", typeof(RuntimeMethodHandle)));
                        else
                            PushUnknownTokenExpression(in instruction, "runtime handle");
                    }
                    else
                    {
                        PushUnknownTokenExpression(in instruction, "runtime handle");
                    }
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Initobj))
                {
                    CSharpExpression address = Pop();
                    string target = address.LValue ?? address.Text;
                    string typeName = FormatResolvedTypeOrToken(in instruction);
                    AppendStatement($"{target} = default({typeName});");
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Cpobj))
                {
                    CSharpExpression source = Pop();
                    CSharpExpression destination = Pop();
                    AppendStatement($"{destination.LValue ?? destination.Text} = {source.LValue ?? source.Text}; /* cpobj {FormatResolvedTypeOrToken(in instruction)} */");
                    return true;
                }

                return false;
            }

            private bool TryRenderIndirectInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Ldobj))
                {
                    CSharpExpression address = Pop();
                    Type? type = GetResolvedType(in instruction);
                    Push(new CSharpExpression(address.LValue ?? $"*({address.Text})", type));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Stobj))
                {
                    CSharpExpression value = Pop();
                    CSharpExpression address = Pop();
                    AppendStatement($"{address.LValue ?? $"*({address.Text})"} = {value.Text}; /* stobj {FormatResolvedTypeOrToken(in instruction)} */");
                    return true;
                }

                Type? loadType = GetIndirectLoadType(instruction.OpCode);
                if (loadType is not null)
                {
                    CSharpExpression address = Pop();
                    Push(new CSharpExpression(address.LValue ?? $"*({address.Text})", loadType));
                    return true;
                }

                Type? storeType = GetIndirectStoreType(instruction.OpCode);
                if (storeType is not null)
                {
                    CSharpExpression value = Pop();
                    CSharpExpression address = Pop();
                    AppendStatement($"{address.LValue ?? $"*({address.Text})"} = ({FormatType(storeType)})({value.Text});");
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Localloc))
                {
                    CSharpExpression size = Pop();
                    Push(new CSharpExpression($"/* localloc */ stackalloc byte[{size.Text}]", typeof(IntPtr)));
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Cpblk) || Is(instruction.OpCode, OpCodes.Initblk))
                {
                    EmitUnsupported(in instruction);
                    return true;
                }

                return false;
            }

            private bool TryRenderTerminalInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Ret))
                {
                    if (_method is MethodInfo methodInfo && methodInfo.ReturnType != typeof(void))
                    {
                        AppendStatement($"return {Pop().Text};");
                    }
                    else if (!IsImplicitFinalVoidReturn(in instruction))
                    {
                        AppendStatement("return;");
                    }
                    _stack.Clear();
                    _reachable = false;
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Throw))
                {
                    AppendStatement($"throw {Pop().Text};");
                    _stack.Clear();
                    _reachable = false;
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Rethrow))
                {
                    AppendStatement("throw;");
                    _stack.Clear();
                    _reachable = false;
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Endfinally))
                {
                    AppendComment($"IL_{instruction.Offset:X4}: endfinally");
                    _stack.Clear();
                    _reachable = false;
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Endfilter))
                {
                    CSharpExpression filterResult = Pop();
                    AppendComment($"IL_{instruction.Offset:X4}: endfilter {filterResult.Text}");
                    _stack.Clear();
                    _reachable = false;
                    return true;
                }

                return false;
            }

            private bool TryRenderPrefixInstruction(in JitIlInstruction instruction)
            {
                if (Is(instruction.OpCode, OpCodes.Constrained))
                {




                    _constrainedType = GetResolvedType(in instruction);
                    return true;
                }

                if (Is(instruction.OpCode, OpCodes.Tailcall) ||
                    Is(instruction.OpCode, OpCodes.Volatile) ||
                    Is(instruction.OpCode, OpCodes.Readonly) ||
                    Is(instruction.OpCode, OpCodes.Unaligned))
                {
                    AppendComment($"IL_{instruction.Offset:X4}: {instruction.OpCode.Name} {JitIlDecoder.FormatOperand(instruction.Operand)}".TrimEnd());
                    return true;
                }

                return false;
            }

            private void StoreLocal(int localIndex)
            {
                CSharpExpression value = Pop();
                if (_elidedConditionLocals.Contains(localIndex))
                {
                    _deferredConditionLocals[localIndex] = value;
                    return;
                }

                AppendStatement($"V_{localIndex} = {value.Text};");
            }

            private bool IsImplicitFinalVoidReturn(in JitIlInstruction instruction)
            {
                if (_instructions.Length == 0 || _labels.Contains(instruction.Offset) || _stack.Count != 0)
                    return false;

                return instruction.Offset == _instructions[_instructions.Length - 1].Offset;
            }

            private CSharpExpression[] PopArguments(ParameterInfo[] parameters)
            {
                CSharpExpression[] arguments = new CSharpExpression[parameters.Length];
                for (int i = parameters.Length - 1; i >= 0; i--)
                    arguments[i] = Pop();
                return arguments;
            }

            private string FormatArguments(CSharpExpression[] arguments, ParameterInfo[] parameters)
            {
                StringBuilder text = new();
                for (int i = 0; i < arguments.Length; i++)
                {
                    if (i != 0)
                        text.Append(", ");

                    ParameterInfo parameter = parameters[i];
                    CSharpExpression argument = arguments[i];
                    if (parameter.ParameterType.IsByRef)
                    {
                        string modifier = parameter.IsOut ? "out " : parameter.IsIn ? "in " : "ref ";
                        Type expectedType = parameter.ParameterType.GetElementType() ?? parameter.ParameterType;
                        text.Append(modifier).Append(argument.LValue ?? FormatExpressionForExpectedType(argument, expectedType));
                    }
                    else
                    {
                        text.Append(FormatExpressionForExpectedType(argument, parameter.ParameterType));
                    }
                }
                return text.ToString();
            }

            private bool TryRenderSpecialNameInvocation(
                MethodInfo methodInfo,
                CSharpExpression? instance,
                CSharpExpression[] arguments,
                out CSharpExpression? result)
            {
                result = null;
                if (!methodInfo.IsSpecialName || methodInfo.DeclaringType is null)
                    return false;

                if (TryFormatOperatorInvocation(methodInfo, arguments, out CSharpExpression operatorResult))
                {
                    result = operatorResult;
                    return true;
                }

                const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;
                foreach (PropertyInfo property in methodInfo.DeclaringType.GetProperties(flags))
                {
                    MethodInfo? getter = property.GetGetMethod(true);
                    MethodInfo? setter = property.GetSetMethod(true);
                    if (SameMethod(methodInfo, getter))
                    {
                        string access = FormatPropertyAccess(property, instance, arguments);
                        result = new CSharpExpression(access, property.PropertyType, access);
                        return true;
                    }

                    if (SameMethod(methodInfo, setter))
                    {
                        ParameterInfo[] indexParameters = property.GetIndexParameters();
                        if (arguments.Length != indexParameters.Length + 1)
                            return false;

                        CSharpExpression[] indexArguments = new CSharpExpression[indexParameters.Length];
                        if (indexArguments.Length != 0)
                            Array.Copy(arguments, indexArguments, indexArguments.Length);

                        string access = FormatPropertyAccess(property, instance, indexArguments);
                        string value = FormatExpressionForExpectedType(arguments[arguments.Length - 1], property.PropertyType);
                        AppendStatement($"{access} = {value};");
                        return true;
                    }
                }

                foreach (EventInfo eventInfo in methodInfo.DeclaringType.GetEvents(flags))
                {
                    MethodInfo? addMethod = eventInfo.GetAddMethod(true);
                    MethodInfo? removeMethod = eventInfo.GetRemoveMethod(true);
                    if (!SameMethod(methodInfo, addMethod) && !SameMethod(methodInfo, removeMethod))
                        continue;

                    if (arguments.Length != 1)
                        return false;

                    string target = FormatMemberTarget(eventInfo.DeclaringType ?? methodInfo.DeclaringType, methodInfo.IsStatic, instance);
                    string operation = SameMethod(methodInfo, addMethod) ? "+=" : "-=";
                    Type expectedType = eventInfo.EventHandlerType ?? arguments[0].Type ?? typeof(Delegate);
                    AppendStatement($"{target}.{EscapeIdentifier(eventInfo.Name)} {operation} {FormatExpressionForExpectedType(arguments[0], expectedType)};");
                    return true;
                }

                return false;
            }

            private static bool TryFormatOperatorInvocation(
                MethodInfo methodInfo,
                CSharpExpression[] arguments,
                out CSharpExpression expression)
            {
                expression = default;
                if (!methodInfo.IsStatic || !methodInfo.IsSpecialName)
                    return false;

                ParameterInfo[] parameters = methodInfo.GetParameters();
                if (arguments.Length != parameters.Length)
                    return false;

                string? binaryOperator = methodInfo.Name switch
                {
                    "op_Equality" => "==",
                    "op_Inequality" => "!=",
                    "op_Addition" => "+",
                    "op_Subtraction" => "-",
                    "op_Multiply" => "*",
                    "op_Division" => "/",
                    "op_Modulus" => "%",
                    "op_BitwiseAnd" => "&",
                    "op_BitwiseOr" => "|",
                    "op_ExclusiveOr" => "^",
                    "op_LeftShift" => "<<",
                    "op_RightShift" => ">>",
                    "op_GreaterThan" => ">",
                    "op_LessThan" => "<",
                    "op_GreaterThanOrEqual" => ">=",
                    "op_LessThanOrEqual" => "<=",
                    _ => null
                };

                if (binaryOperator is not null && arguments.Length == 2)
                {
                    string left = FormatExpressionForExpectedType(arguments[0], parameters[0].ParameterType);
                    string right = FormatExpressionForExpectedType(arguments[1], parameters[1].ParameterType);
                    expression = new CSharpExpression($"({left} {binaryOperator} {right})", methodInfo.ReturnType);
                    return true;
                }

                string? unaryOperator = methodInfo.Name switch
                {
                    "op_LogicalNot" => "!",
                    "op_OnesComplement" => "~",
                    "op_UnaryNegation" => "-",
                    "op_UnaryPlus" => "+",
                    _ => null
                };

                if (unaryOperator is not null && arguments.Length == 1)
                {
                    string operand = FormatExpressionForExpectedType(arguments[0], parameters[0].ParameterType);
                    expression = new CSharpExpression($"({unaryOperator}{operand})", methodInfo.ReturnType);
                    return true;
                }

                if ((methodInfo.Name == "op_Implicit" || methodInfo.Name == "op_Explicit") && arguments.Length == 1)
                {
                    string operand = FormatExpressionForExpectedType(arguments[0], parameters[0].ParameterType);
                    expression = new CSharpExpression($"(({FormatType(methodInfo.ReturnType)})({operand}))", methodInfo.ReturnType);
                    return true;
                }

                return false;
            }

            private static string FormatPropertyAccess(
                PropertyInfo property,
                CSharpExpression? instance,
                CSharpExpression[] indexArguments)
            {
                MethodInfo? accessor = property.GetGetMethod(true) ?? property.GetSetMethod(true);
                bool isStatic = accessor?.IsStatic == true;
                string target = FormatMemberTarget(property.DeclaringType ?? typeof(object), isStatic, instance);
                ParameterInfo[] indexParameters = property.GetIndexParameters();
                if (indexParameters.Length == 0)
                    return target + "." + EscapeIdentifier(property.Name);

                StringBuilder indexes = new();
                for (int i = 0; i < indexArguments.Length; i++)
                {
                    if (i != 0)
                        indexes.Append(", ");
                    Type expected = i < indexParameters.Length ? indexParameters[i].ParameterType : indexArguments[i].Type ?? typeof(object);
                    indexes.Append(FormatExpressionForExpectedType(indexArguments[i], expected));
                }
                return target + "[" + indexes + "]";
            }

            private static string FormatMemberTarget(Type declaringType, bool isStatic, CSharpExpression? instance)
            {
                if (isStatic)
                    return FormatType(declaringType);
                if (!instance.HasValue || instance.Value.Text == "this")
                    return "this";
                return ParenthesizeTarget(instance.Value.Text);
            }

            private static bool SameMethod(MethodInfo? left, MethodInfo? right)
            {
                if (left is null || right is null)
                    return false;
                if (ReferenceEquals(left, right) || left.Equals(right))
                    return true;
                try
                {
                    return left.Module.Equals(right.Module) && left.MetadataToken == right.MetadataToken;
                }
                catch
                {
                    return false;
                }
            }

            private static bool TryFormatDelegateConstruction(
                ConstructorInfo constructor,
                CSharpExpression[] arguments,
                [NotNullWhen(true)] out string? expression)
            {
                expression = null;
                Type? delegateType = constructor.DeclaringType;
                if (delegateType is null || !typeof(Delegate).IsAssignableFrom(delegateType) || arguments.Length != 2)
                    return false;

                CSharpExpression functionPointer = arguments[1];
                MethodBase? target = functionPointer.FunctionPointerTarget;
                if (target is null)
                    return false;

                string methodGroup;
                if (target.IsStatic)
                {
                    methodGroup = FormatMethodReference(target);
                }
                else
                {
                    string owner = functionPointer.FunctionPointerInstance ?? arguments[0].Text;
                    methodGroup = ParenthesizeTarget(owner) + "." + EscapeIdentifier(target.Name);
                }

                expression = $"new {FormatType(delegateType)}({methodGroup})";
                return true;
            }

            private bool ShouldRenderBaseCall(OpCode opCode, MethodInfo methodInfo, CSharpExpression? instance)
            {
                if (!Is(opCode, OpCodes.Call) || methodInfo.IsStatic || !methodInfo.IsVirtual || !instance.HasValue || instance.Value.Text != "this")
                    return false;

                Type? currentType = _method.DeclaringType;
                Type? declaringType = methodInfo.DeclaringType;
                return currentType is not null && declaringType is not null && currentType != declaringType && declaringType.IsAssignableFrom(currentType);
            }

            private string FormatMethodInvocation(
                MethodInfo methodInfo,
                CSharpExpression? instance,
                CSharpExpression[] arguments,
                ParameterInfo[] parameters,
                bool useBaseTarget)
            {
                StringBuilder invocation = new();

                if (methodInfo.IsStatic)
                {
                    invocation.Append(FormatType(methodInfo.DeclaringType ?? typeof(object))).Append('.');
                }
                else if (useBaseTarget)
                {
                    invocation.Append("base.");
                }
                else if (instance.HasValue)
                {
                    if (instance.Value.Text != "this")
                        invocation.Append(ParenthesizeTarget(instance.Value.Text)).Append('.');
                }

                invocation.Append(EscapeIdentifier(methodInfo.Name));
                if (methodInfo.IsGenericMethod)
                {
                    Type[] genericArguments = methodInfo.GetGenericArguments();
                    invocation.Append('<');
                    for (int i = 0; i < genericArguments.Length; i++)
                    {
                        if (i != 0)
                            invocation.Append(", ");
                        invocation.Append(FormatType(genericArguments[i]));
                    }
                    invocation.Append('>');
                }

                invocation.Append('(').Append(FormatArguments(arguments, parameters)).Append(')');
                return invocation.ToString();
            }

            private CSharpExpression GetArgumentExpression(int ilIndex)
            {
                if (!_method.IsStatic)
                {
                    if (ilIndex == 0)
                        return new CSharpExpression("this", _method.DeclaringType, "this");
                    ilIndex--;
                }

                if ((uint)ilIndex >= (uint)_parameters.Length)
                    return new CSharpExpression($"arg_{ilIndex}", null, $"arg_{ilIndex}");

                ParameterInfo parameter = _parameters[ilIndex];
                Type parameterType = parameter.ParameterType;
                if (parameterType.IsByRef)
                    parameterType = parameterType.GetElementType() ?? parameterType;

                string name = EscapeIdentifier(GetParameterName(parameter, ilIndex));
                return new CSharpExpression(name, parameterType, name);
            }

            private CSharpExpression GetLocalExpression(int localIndex)
            {
                Type? type = _locals.TryGetValue(localIndex, out LocalVariableInfo? local) ? local.LocalType : null;
                string name = "V_" + localIndex.ToString(CultureInfo.InvariantCulture);
                return new CSharpExpression(name, type, name);
            }

            private static int GetVariableIndex(in JitIlInstruction instruction)
            {
                int index = GetVariableIndexCore(in instruction);
                if (index >= 0)
                    return index;
                throw new BadImageFormatException($"Missing variable index for {instruction.OpCode.Name} at IL_{instruction.Offset:X4}.");
            }

            private static int GetBranchTarget(in JitIlInstruction instruction)
            {
                if (instruction.Operand is int target)
                    return target;
                throw new BadImageFormatException($"Missing branch target for {instruction.OpCode.Name} at IL_{instruction.Offset:X4}.");
            }

            private void EmitUnsupported(in JitIlInstruction instruction)
            {
                AppendComment($"IL_{instruction.Offset:X4}: {instruction.OpCode.Name} {JitIlDecoder.FormatOperand(instruction.Operand)} [kept as IL; no safe C# projection]".TrimEnd());
                ApplyUnknownStackBehaviour(instruction.OpCode);
            }

            private void ApplyUnknownStackBehaviour(OpCode opCode)
            {
                int popCount = GetFixedPopCount(opCode.StackBehaviourPop);
                if (popCount < 0)
                {
                    _stack.Clear();
                }
                else
                {
                    for (int i = 0; i < popCount && _stack.Count != 0; i++)
                        _stack.RemoveAt(_stack.Count - 1);
                }

                int pushCount = GetFixedPushCount(opCode.StackBehaviourPush);
                if (pushCount < 0)
                {
                    Push(new CSharpExpression("/* unknown stack result */ default", null));
                }
                else
                {
                    for (int i = 0; i < pushCount; i++)
                        Push(new CSharpExpression("/* unknown stack result */ default", null));
                }
            }

            private CSharpExpression Pop()
            {
                if (_stack.Count == 0)
                    return new CSharpExpression("/* stack underflow */ default", null);

                int last = _stack.Count - 1;
                CSharpExpression value = _stack[last];
                _stack.RemoveAt(last);
                return value;
            }

            private CSharpExpression Peek()
            {
                return _stack.Count == 0
                    ? new CSharpExpression("/* stack underflow */ default", null)
                    : _stack[_stack.Count - 1];
            }

            private void Push(CSharpExpression expression) => _stack.Add(expression);

            private void PushUnknownTokenExpression(in JitIlInstruction instruction, string purpose)
            {
                Push(new CSharpExpression($"/* unresolved {purpose}: {JitIlDecoder.FormatOperand(instruction.Operand)} */ default", null));
            }

            private void AppendStatement(string statement) => _output.Append("        ").AppendLine(statement);

            private void AppendComment(string comment) => _output.Append("        // ").AppendLine(comment);
        }

        private static string PolishStructuredControlFlow(string renderedMethod)
        {
            if (string.IsNullOrEmpty(renderedMethod))
                return renderedMethod;

            string newline = Environment.NewLine;
            string[] split = renderedMethod.Split(new[] { newline }, StringSplitOptions.None);
            List<string> lines = new(split);

            RemoveCollapsedMergeScaffolds(lines);
            StructureForwardIfElse(lines);
            StructureForwardIf(lines);
            InlineAdjacentCopyTemps(lines);
            InlineImmediateConditionTemps(lines);
            RemoveTrailingVoidReturn(lines);

            return string.Join(newline, lines.ToArray());
        }

        private static void RemoveCollapsedMergeScaffolds(List<string> lines)
        {
            for (int i = 0; i + 3 < lines.Count;)
            {
                if (!TryParseConditionalGoto(lines[i], out _, out string branchLabel) ||
                    !TryParseUnconditionalGoto(lines[i + 1], out string mergeLabel) ||
                    !IsExactLabel(lines[i + 2], branchLabel) ||
                    !IsExactLabel(lines[i + 3], mergeLabel) ||
                    CountLabelReferences(lines, branchLabel) != 2 ||
                    CountLabelReferences(lines, mergeLabel) != 2)
                {
                    i++;
                    continue;
                }




                lines.RemoveRange(i, 4);
            }
        }

        private static void StructureForwardIfElse(List<string> lines)
        {
            for (int i = 0; i < lines.Count; i++)
            {
                if (!TryParseConditionalGoto(lines[i], out string branchCondition, out string elseLabel))
                    continue;

                int elseIndex = FindLabel(lines, elseLabel, i + 1);
                if (elseIndex <= i + 1)
                    continue;

                int jumpIndex = elseIndex - 1;
                if (!TryParseUnconditionalGoto(lines[jumpIndex], out string endLabel))
                    continue;

                int endIndex = FindLabel(lines, endLabel, elseIndex + 1);
                if (endIndex <= elseIndex + 1 ||
                    CountLabelReferences(lines, elseLabel) != 2 ||
                    CountLabelReferences(lines, endLabel) != 2 ||
                    ContainsControlFlow(lines, i + 1, jumpIndex) ||
                    ContainsControlFlow(lines, elseIndex + 1, endIndex))
                {
                    continue;
                }

                string fallthroughCondition = NegateCondition(branchCondition);
                List<string> replacement = new();
                replacement.Add("        if (" + fallthroughCondition + ")");
                replacement.Add("        {");
                AppendIndentedRange(lines, replacement, i + 1, jumpIndex, 4);
                replacement.Add("        }");
                replacement.Add("        else");
                replacement.Add("        {");
                AppendIndentedRange(lines, replacement, elseIndex + 1, endIndex, 4);
                replacement.Add("        }");

                int removeCount = endIndex - i + 1;
                lines.RemoveRange(i, removeCount);
                lines.InsertRange(i, replacement);
                i += replacement.Count - 1;
            }
        }

        private static void StructureForwardIf(List<string> lines)
        {
            for (int i = 0; i < lines.Count; i++)
            {
                if (!TryParseConditionalGoto(lines[i], out string branchCondition, out string endLabel))
                    continue;

                int endIndex = FindLabel(lines, endLabel, i + 1);
                if (endIndex <= i + 1 ||
                    CountLabelReferences(lines, endLabel) != 2 ||
                    ContainsControlFlow(lines, i + 1, endIndex))
                {
                    continue;
                }

                string fallthroughCondition = NegateCondition(branchCondition);
                List<string> replacement = new();
                replacement.Add("        if (" + fallthroughCondition + ")");
                replacement.Add("        {");
                AppendIndentedRange(lines, replacement, i + 1, endIndex, 4);
                replacement.Add("        }");

                int removeCount = endIndex - i + 1;
                lines.RemoveRange(i, removeCount);
                lines.InsertRange(i, replacement);
                i += replacement.Count - 1;
            }
        }

        private static void InlineAdjacentCopyTemps(List<string> lines)
        {
            for (int declarationIndex = 0; declarationIndex < lines.Count; declarationIndex++)
            {
                if (!TryParseLocalDeclaration(lines[declarationIndex], out string localName) ||
                    CountIdentifierReferences(lines, localName) != 3)
                {
                    continue;
                }

                for (int assignmentIndex = declarationIndex + 1; assignmentIndex + 1 < lines.Count; assignmentIndex++)
                {
                    string assignment = lines[assignmentIndex].Trim();
                    string prefix = localName + " = ";
                    if (!assignment.StartsWith(prefix, StringComparison.Ordinal) || !assignment.EndsWith(";", StringComparison.Ordinal))
                        continue;

                    string destination = lines[assignmentIndex + 1].Trim();
                    string suffix = " = " + localName + ";";
                    if (!destination.EndsWith(suffix, StringComparison.Ordinal))
                        break;

                    string expression = assignment.Substring(prefix.Length, assignment.Length - prefix.Length - 1);
                    string destinationPrefix = destination.Substring(0, destination.Length - localName.Length - 1);
                    int leadingWhitespace = lines[assignmentIndex + 1].Length - lines[assignmentIndex + 1].TrimStart().Length;
                    lines[assignmentIndex + 1] = new string(' ', leadingWhitespace) + destinationPrefix + expression + ";";

                    lines.RemoveAt(assignmentIndex);
                    lines.RemoveAt(declarationIndex);
                    if (declarationIndex < lines.Count && lines[declarationIndex].Length == 0 &&
                        declarationIndex > 0 && lines[declarationIndex - 1].Trim() == "{")
                    {
                        lines.RemoveAt(declarationIndex);
                    }
                    declarationIndex--;
                    break;
                }
            }
        }

        private static void InlineImmediateConditionTemps(List<string> lines)
        {
            for (int declarationIndex = 0; declarationIndex < lines.Count; declarationIndex++)
            {
                if (!TryParseLocalDeclaration(lines[declarationIndex], out string localName) ||
                    CountIdentifierReferences(lines, localName) != 3)
                {
                    continue;
                }

                string prefix = localName + " = ";
                int assignmentIndex = -1;
                for (int i = declarationIndex + 1; i < lines.Count; i++)
                {
                    string candidate = lines[i].Trim();
                    if (candidate.StartsWith(prefix, StringComparison.Ordinal) &&
                        candidate.EndsWith(";", StringComparison.Ordinal))
                    {
                        assignmentIndex = i;
                        break;
                    }
                }

                if (assignmentIndex < 0)
                    continue;

                string assignment = lines[assignmentIndex].Trim();
                int conditionIndex = NextNonBlankLine(lines, assignmentIndex + 1);
                if (conditionIndex < 0 ||
                    !TryReplaceExactConditionLocal(lines[conditionIndex], localName,
                        assignment.Substring(prefix.Length, assignment.Length - prefix.Length - 1),
                        out string replacedCondition))
                {
                    continue;
                }





                lines[conditionIndex] = replacedCondition;
                lines.RemoveAt(assignmentIndex);
                lines.RemoveAt(declarationIndex);

                if (declarationIndex < lines.Count && lines[declarationIndex].Length == 0 &&
                    declarationIndex > 0 && lines[declarationIndex - 1].Trim() == "{")
                {
                    lines.RemoveAt(declarationIndex);
                }

                declarationIndex--;
            }
        }

        private static int NextNonBlankLine(List<string> lines, int startIndex)
        {
            for (int i = startIndex; i < lines.Count; i++)
            {
                if (lines[i].Length != 0)
                    return i;
            }

            return -1;
        }

        private static bool TryReplaceExactConditionLocal(
            string line,
            string localName,
            string expression,
            out string replacement)
        {
            int leadingWhitespace = line.Length - line.TrimStart().Length;
            string trimmed = line.Trim();
            string direct = "if (" + localName + ")";
            string negated = "if (!(" + localName + "))";

            if (trimmed == direct)
            {
                replacement = new string(' ', leadingWhitespace) + "if (" + expression + ")";
                return true;
            }

            if (trimmed == negated)
            {
                replacement = new string(' ', leadingWhitespace) + "if (!(" + expression + "))";
                return true;
            }

            replacement = string.Empty;
            return false;
        }

        private static bool TryParseLocalDeclaration(string line, out string localName)
        {
            string trimmed = line.Trim();
            int leadingWhitespace = line.Length - line.TrimStart().Length;
            if (leadingWhitespace != 4 || trimmed.IndexOf('=') >= 0 || !trimmed.EndsWith(";", StringComparison.Ordinal))
            {
                localName = string.Empty;
                return false;
            }

            int lastSpace = trimmed.LastIndexOf(' ');
            if (lastSpace < 0 || lastSpace + 1 >= trimmed.Length - 1)
            {
                localName = string.Empty;
                return false;
            }

            localName = trimmed.Substring(lastSpace + 1, trimmed.Length - lastSpace - 2);
            if (!localName.StartsWith("V_", StringComparison.Ordinal) || localName.Length <= 2)
                return false;

            for (int i = 2; i < localName.Length; i++)
            {
                if (!char.IsDigit(localName[i]))
                    return false;
            }
            return true;
        }

        private static int CountIdentifierReferences(List<string> lines, string identifier)
        {
            int count = 0;
            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i];
                int search = 0;
                while (search < line.Length)
                {
                    int match = line.IndexOf(identifier, search, StringComparison.Ordinal);
                    if (match < 0)
                        break;

                    int before = match - 1;
                    int after = match + identifier.Length;
                    bool beforeBoundary = before < 0 || !IsIdentifierPart(line[before]);
                    bool afterBoundary = after >= line.Length || !IsIdentifierPart(line[after]);
                    if (beforeBoundary && afterBoundary)
                        count++;

                    search = match + identifier.Length;
                }
            }
            return count;
        }

        private static bool IsIdentifierPart(char value) =>
            char.IsLetterOrDigit(value) || value == '_';

        private static void RemoveTrailingVoidReturn(List<string> lines)
        {
            if (lines.Count < 3)
                return;

            int closingBrace = lines.Count - 1;
            while (closingBrace >= 0 && lines[closingBrace].Length == 0)
                closingBrace--;

            if (closingBrace <= 0 || lines[closingBrace].Trim() != "}")
                return;

            int candidate = closingBrace - 1;
            while (candidate >= 0 && lines[candidate].Length == 0)
                candidate--;

            if (candidate >= 0 && lines[candidate].Trim() == "return;")
                lines.RemoveAt(candidate);
        }

        private static bool ContainsControlFlow(List<string> lines, int startInclusive, int endExclusive)
        {
            for (int i = startInclusive; i < endExclusive; i++)
            {
                string trimmed = lines[i].Trim();
                if (trimmed.StartsWith("IL_", StringComparison.Ordinal) ||
                    trimmed.StartsWith("goto IL_", StringComparison.Ordinal) ||
                    (trimmed.StartsWith("if (", StringComparison.Ordinal) && trimmed.IndexOf(") goto IL_", StringComparison.Ordinal) >= 0) ||
                    trimmed.StartsWith("switch (", StringComparison.Ordinal))
                {
                    return true;
                }
            }
            return false;
        }

        private static void AppendIndentedRange(
            List<string> source,
            List<string> destination,
            int startInclusive,
            int endExclusive,
            int spaces)
        {
            string indent = new string(' ', spaces);
            for (int i = startInclusive; i < endExclusive; i++)
            {
                if (source[i].Length == 0)
                    destination.Add(source[i]);
                else
                    destination.Add(indent + source[i]);
            }
        }

        private static int FindLabel(List<string> lines, string label, int startIndex)
        {
            for (int i = startIndex; i < lines.Count; i++)
            {
                if (IsExactLabel(lines[i], label))
                    return i;
            }
            return -1;
        }

        private static int CountLabelReferences(List<string> lines, string label)
        {
            int count = 0;
            for (int i = 0; i < lines.Count; i++)
            {
                string line = lines[i];
                int start = 0;
                while (start < line.Length)
                {
                    int match = line.IndexOf(label, start, StringComparison.Ordinal);
                    if (match < 0)
                        break;
                    count++;
                    start = match + label.Length;
                }
            }
            return count;
        }

        private static bool IsExactLabel(string line, string label) =>
            string.Equals(line.Trim(), label + ":", StringComparison.Ordinal);

        private static bool TryParseUnconditionalGoto(string line, out string label)
        {
            string trimmed = line.Trim();
            const string prefix = "goto ";
            if (!trimmed.StartsWith(prefix, StringComparison.Ordinal) || !trimmed.EndsWith(";", StringComparison.Ordinal))
            {
                label = string.Empty;
                return false;
            }

            label = trimmed.Substring(prefix.Length, trimmed.Length - prefix.Length - 1);
            return label.StartsWith("IL_", StringComparison.Ordinal);
        }

        private static bool TryParseConditionalGoto(string line, out string condition, out string label)
        {
            string trimmed = line.Trim();
            const string prefix = "if (";
            const string marker = ") goto ";
            if (!trimmed.StartsWith(prefix, StringComparison.Ordinal) || !trimmed.EndsWith(";", StringComparison.Ordinal))
            {
                condition = string.Empty;
                label = string.Empty;
                return false;
            }

            int markerIndex = trimmed.LastIndexOf(marker, StringComparison.Ordinal);
            if (markerIndex < prefix.Length)
            {
                condition = string.Empty;
                label = string.Empty;
                return false;
            }

            condition = trimmed.Substring(prefix.Length, markerIndex - prefix.Length);
            int labelStart = markerIndex + marker.Length;
            label = trimmed.Substring(labelStart, trimmed.Length - labelStart - 1);
            return label.StartsWith("IL_", StringComparison.Ordinal);
        }

        private static string NegateCondition(string condition)
        {
            string trimmed = condition.Trim();
            if (trimmed.StartsWith("!(", StringComparison.Ordinal) && trimmed.EndsWith(")", StringComparison.Ordinal))
            {
                string inner = trimmed.Substring(2, trimmed.Length - 3).Trim();
                return TrimRedundantOuterParentheses(inner);
            }

            return "!(" + trimmed + ")";
        }

        private static string TrimRedundantOuterParentheses(string expression)
        {
            string current = expression.Trim();
            while (current.Length >= 2 && current[0] == '(' && current[current.Length - 1] == ')' && HasSingleOuterParenthesisPair(current))
                current = current.Substring(1, current.Length - 2).Trim();
            return current;
        }

        private static bool HasSingleOuterParenthesisPair(string expression)
        {
            int depth = 0;
            bool inString = false;
            bool escape = false;

            for (int i = 0; i < expression.Length; i++)
            {
                char c = expression[i];
                if (inString)
                {
                    if (escape)
                    {
                        escape = false;
                        continue;
                    }
                    if (c == '\\')
                    {
                        escape = true;
                        continue;
                    }
                    if (c == '"')
                        inString = false;
                    continue;
                }

                if (c == '"')
                {
                    inString = true;
                    continue;
                }

                if (c == '(')
                    depth++;
                else if (c == ')')
                {
                    depth--;
                    if (depth == 0 && i != expression.Length - 1)
                        return false;
                }
            }

            return depth == 0;
        }

        private readonly record struct CSharpExpression(
            string Text,
            Type? Type,
            string? LValue = null,
            bool IsAddress = false,
            MethodBase? FunctionPointerTarget = null,
            string? FunctionPointerInstance = null)
        {
            public CSharpExpression AsAddress() => new(Text, Type, LValue ?? Text, true, FunctionPointerTarget, FunctionPointerInstance);
        }

        private readonly record struct BranchDecision(int BranchOffset, string Test, bool Taken);

        private readonly record struct FlowState(
            ImmutableArray<CSharpExpression> Stack,
            ImmutableArray<BranchDecision> Path);

        private static Dictionary<int, LocalVariableInfo> GetLocals(MethodBase method)
        {
            Dictionary<int, LocalVariableInfo> locals = new();
            try
            {
                MethodBody? body = method.GetMethodBody();
                if (body is null)
                    return locals;

                foreach (LocalVariableInfo local in body.LocalVariables)
                    locals[local.LocalIndex] = local;
            }
            catch
            {
            }
            return locals;
        }

        private static FrozenSet<int> BuildElidedTailReturnLocals(
            ImmutableArray<JitIlInstruction> instructions,
            in JitMethodBodyMetadata body)
        {
            HashSet<int> candidates = new();
            if (body.ExceptionRegions.Length != 0)
                return candidates.ToFrozenSet();

            Dictionary<int, int> localReferences = new();
            Dictionary<int, int> branchReferences = new();

            for (int i = 0; i < instructions.Length; i++)
            {
                JitIlInstruction instruction = instructions[i];
                if (TryGetReferencedLocalIndexCore(in instruction, out int localIndex))
                    localReferences[localIndex] = localReferences.TryGetValue(localIndex, out int count) ? count + 1 : 1;

                if (IsBranchOperand(instruction.OpCode) && instruction.Operand is int target)
                    branchReferences[target] = branchReferences.TryGetValue(target, out int branchCount) ? branchCount + 1 : 1;
                else if (Is(instruction.OpCode, OpCodes.Switch) && instruction.Operand is ImmutableArray<int> targets)
                {
                    for (int j = 0; j < targets.Length; j++)
                    {
                        int switchTarget = targets[j];
                        branchReferences[switchTarget] = branchReferences.TryGetValue(switchTarget, out int switchCount) ? switchCount + 1 : 1;
                    }
                }
            }

            for (int i = 0; i + 3 < instructions.Length; i++)
            {
                JitIlInstruction store = instructions[i];
                JitIlInstruction branch = instructions[i + 1];
                JitIlInstruction load = instructions[i + 2];
                JitIlInstruction ret = instructions[i + 3];

                if (!TryGetStoredLocalIndexCore(in store, out int localIndex) ||
                    (!Is(branch.OpCode, OpCodes.Br) && !Is(branch.OpCode, OpCodes.Br_S)) ||
                    branch.Operand is not int target || target != load.Offset ||
                    !TryGetLoadedLocalIndexCore(in load, out int loadedLocal) || loadedLocal != localIndex ||
                    !Is(ret.OpCode, OpCodes.Ret))
                {
                    continue;
                }

                if (localReferences.TryGetValue(localIndex, out int localCount) && localCount == 2 &&
                    branchReferences.TryGetValue(load.Offset, out int targetCount) && targetCount == 1)
                {
                    candidates.Add(localIndex);
                }
            }

            return candidates.ToFrozenSet();
        }

        private static FrozenSet<int> BuildElidedConditionLocals(
            ImmutableArray<JitIlInstruction> instructions,
            in JitMethodBodyMetadata body)
        {
            HashSet<int> candidates = new();
            if (body.ExceptionRegions.Length != 0)
                return candidates.ToFrozenSet();

            Dictionary<int, int> localReferences = new();
            HashSet<int> branchTargets = new();
            for (int i = 0; i < instructions.Length; i++)
            {
                JitIlInstruction instruction = instructions[i];
                if (TryGetReferencedLocalIndexCore(in instruction, out int localIndex))
                    localReferences[localIndex] = localReferences.TryGetValue(localIndex, out int count) ? count + 1 : 1;

                if (IsBranchOperand(instruction.OpCode) && instruction.Operand is int target)
                    branchTargets.Add(target);
                else if (Is(instruction.OpCode, OpCodes.Switch) && instruction.Operand is ImmutableArray<int> targets)
                {
                    for (int j = 0; j < targets.Length; j++)
                        branchTargets.Add(targets[j]);
                }
            }

            for (int i = 0; i + 2 < instructions.Length; i++)
            {
                JitIlInstruction store = instructions[i];
                JitIlInstruction load = instructions[i + 1];
                JitIlInstruction branch = instructions[i + 2];

                if (!TryGetStoredLocalIndexCore(in store, out int localIndex) ||
                    !TryGetLoadedLocalIndexCore(in load, out int loadedLocal) || loadedLocal != localIndex ||
                    !IsConditionalBranch(branch.OpCode))
                {
                    continue;
                }

                if (localReferences.TryGetValue(localIndex, out int localCount) && localCount == 2 &&
                    !branchTargets.Contains(load.Offset))
                {
                    candidates.Add(localIndex);
                }
            }

            return candidates.ToFrozenSet();
        }

        private static bool IsConditionalBranch(OpCode opCode) =>
            Is(opCode, OpCodes.Brtrue) || Is(opCode, OpCodes.Brtrue_S) ||
            Is(opCode, OpCodes.Brfalse) || Is(opCode, OpCodes.Brfalse_S) ||
            GetBranchComparisonOperator(opCode) is not null;

        private static bool TryGetStoredLocalIndexCore(in JitIlInstruction instruction, out int localIndex)
        {
            if (Is(instruction.OpCode, OpCodes.Stloc_0)) localIndex = 0;
            else if (Is(instruction.OpCode, OpCodes.Stloc_1)) localIndex = 1;
            else if (Is(instruction.OpCode, OpCodes.Stloc_2)) localIndex = 2;
            else if (Is(instruction.OpCode, OpCodes.Stloc_3)) localIndex = 3;
            else if (Is(instruction.OpCode, OpCodes.Stloc) || Is(instruction.OpCode, OpCodes.Stloc_S)) localIndex = GetVariableIndexCore(in instruction);
            else { localIndex = -1; return false; }
            return true;
        }

        private static bool TryGetLoadedLocalIndexCore(in JitIlInstruction instruction, out int localIndex)
        {
            if (Is(instruction.OpCode, OpCodes.Ldloc_0)) localIndex = 0;
            else if (Is(instruction.OpCode, OpCodes.Ldloc_1)) localIndex = 1;
            else if (Is(instruction.OpCode, OpCodes.Ldloc_2)) localIndex = 2;
            else if (Is(instruction.OpCode, OpCodes.Ldloc_3)) localIndex = 3;
            else if (Is(instruction.OpCode, OpCodes.Ldloc) || Is(instruction.OpCode, OpCodes.Ldloc_S)) localIndex = GetVariableIndexCore(in instruction);
            else { localIndex = -1; return false; }
            return true;
        }

        private static bool TryGetReferencedLocalIndexCore(in JitIlInstruction instruction, out int localIndex)
        {
            if (TryGetStoredLocalIndexCore(in instruction, out localIndex) || TryGetLoadedLocalIndexCore(in instruction, out localIndex))
                return true;
            if (Is(instruction.OpCode, OpCodes.Ldloca) || Is(instruction.OpCode, OpCodes.Ldloca_S))
            {
                localIndex = GetVariableIndexCore(in instruction);
                return true;
            }
            localIndex = -1;
            return false;
        }

        private static int GetVariableIndexCore(in JitIlInstruction instruction)
        {
            return instruction.Operand switch
            {
                int value => value,
                byte value => value,
                ushort value => value,
                _ => -1
            };
        }

        private static FrozenSet<int> BuildLabelSet(
            ImmutableArray<JitIlInstruction> instructions,
            in JitMethodBodyMetadata body)
        {
            HashSet<int> labels = new();
            foreach (JitIlInstruction instruction in instructions)
            {
                if (instruction.Operand is int branchTarget && IsBranchOperand(instruction.OpCode))
                {
                    labels.Add(branchTarget);
                }
                else if (instruction.Operand is ImmutableArray<int> switchTargets && Is(instruction.OpCode, OpCodes.Switch))
                {
                    foreach (int target in switchTargets)
                        labels.Add(target);
                }
            }

            foreach (JitExceptionRegion region in body.ExceptionRegions)
            {
                labels.Add(region.TryOffset);
                labels.Add(region.HandlerOffset);
                if (region.Kind == JitExceptionRegionKind.Filter)
                    labels.Add(region.FilterOffset);
            }

            return labels.ToFrozenSet();
        }

        private static bool TryGetResolvedTokenValue(
            in JitIlInstruction instruction,
            [NotNullWhen(true)] out object? value)
        {
            if (instruction.Operand is JitIlTokenOperand tokenOperand && tokenOperand.Value is not null)
            {
                value = tokenOperand.Value;
                return true;
            }

            value = null;
            return false;
        }

        private static Type? GetResolvedType(in JitIlInstruction instruction)
        {
            return TryGetResolvedTokenValue(in instruction, out object? value) && value is Type type ? type : null;
        }

        private static string FormatResolvedTypeOrToken(in JitIlInstruction instruction)
        {
            Type? type = GetResolvedType(in instruction);
            return type is null ? JitIlDecoder.FormatOperand(instruction.Operand) : FormatType(type);
        }

        private static int? GetInt32Constant(in JitIlInstruction instruction)
        {
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_M1)) return -1;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_0)) return 0;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_1)) return 1;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_2)) return 2;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_3)) return 3;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_4)) return 4;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_5)) return 5;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_6)) return 6;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_7)) return 7;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_8)) return 8;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4) && instruction.Operand is int int32) return int32;
            if (Is(instruction.OpCode, OpCodes.Ldc_I4_S) && instruction.Operand is sbyte shortInt32) return shortInt32;
            return null;
        }

        private static string? GetBinaryOperator(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Add) || Is(opCode, OpCodes.Add_Ovf) || Is(opCode, OpCodes.Add_Ovf_Un)) return "+";
            if (Is(opCode, OpCodes.Sub) || Is(opCode, OpCodes.Sub_Ovf) || Is(opCode, OpCodes.Sub_Ovf_Un)) return "-";
            if (Is(opCode, OpCodes.Mul) || Is(opCode, OpCodes.Mul_Ovf) || Is(opCode, OpCodes.Mul_Ovf_Un)) return "*";
            if (Is(opCode, OpCodes.Div) || Is(opCode, OpCodes.Div_Un)) return "/";
            if (Is(opCode, OpCodes.Rem) || Is(opCode, OpCodes.Rem_Un)) return "%";
            if (Is(opCode, OpCodes.And)) return "&";
            if (Is(opCode, OpCodes.Or)) return "|";
            if (Is(opCode, OpCodes.Xor)) return "^";
            if (Is(opCode, OpCodes.Shl)) return "<<";
            if (Is(opCode, OpCodes.Shr) || Is(opCode, OpCodes.Shr_Un)) return ">>";
            return null;
        }

        private static bool IsOverflowChecked(OpCode opCode) =>
            Is(opCode, OpCodes.Add_Ovf) || Is(opCode, OpCodes.Add_Ovf_Un) ||
            Is(opCode, OpCodes.Sub_Ovf) || Is(opCode, OpCodes.Sub_Ovf_Un) ||
            Is(opCode, OpCodes.Mul_Ovf) || Is(opCode, OpCodes.Mul_Ovf_Un);

        private static bool IsUnsignedArithmetic(OpCode opCode) =>
            Is(opCode, OpCodes.Add_Ovf_Un) || Is(opCode, OpCodes.Sub_Ovf_Un) || Is(opCode, OpCodes.Mul_Ovf_Un) ||
            Is(opCode, OpCodes.Div_Un) || Is(opCode, OpCodes.Rem_Un) || Is(opCode, OpCodes.Shr_Un);

        private static string? GetComparisonOperator(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Ceq)) return "==";
            if (Is(opCode, OpCodes.Cgt) || Is(opCode, OpCodes.Cgt_Un)) return ">";
            if (Is(opCode, OpCodes.Clt) || Is(opCode, OpCodes.Clt_Un)) return "<";
            return null;
        }

        private static bool IsUnsignedComparison(OpCode opCode) => Is(opCode, OpCodes.Cgt_Un) || Is(opCode, OpCodes.Clt_Un);

        private static string? GetBranchComparisonOperator(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Beq) || Is(opCode, OpCodes.Beq_S)) return "==";
            if (Is(opCode, OpCodes.Bne_Un) || Is(opCode, OpCodes.Bne_Un_S)) return "!=";
            if (Is(opCode, OpCodes.Bge) || Is(opCode, OpCodes.Bge_S) || Is(opCode, OpCodes.Bge_Un) || Is(opCode, OpCodes.Bge_Un_S)) return ">=";
            if (Is(opCode, OpCodes.Bgt) || Is(opCode, OpCodes.Bgt_S) || Is(opCode, OpCodes.Bgt_Un) || Is(opCode, OpCodes.Bgt_Un_S)) return ">";
            if (Is(opCode, OpCodes.Ble) || Is(opCode, OpCodes.Ble_S) || Is(opCode, OpCodes.Ble_Un) || Is(opCode, OpCodes.Ble_Un_S)) return "<=";
            if (Is(opCode, OpCodes.Blt) || Is(opCode, OpCodes.Blt_S) || Is(opCode, OpCodes.Blt_Un) || Is(opCode, OpCodes.Blt_Un_S)) return "<";
            return null;
        }

        private static bool IsUnsignedBranchComparison(OpCode opCode) =>
            Is(opCode, OpCodes.Bne_Un) || Is(opCode, OpCodes.Bne_Un_S) ||
            Is(opCode, OpCodes.Bge_Un) || Is(opCode, OpCodes.Bge_Un_S) ||
            Is(opCode, OpCodes.Bgt_Un) || Is(opCode, OpCodes.Bgt_Un_S) ||
            Is(opCode, OpCodes.Ble_Un) || Is(opCode, OpCodes.Ble_Un_S) ||
            Is(opCode, OpCodes.Blt_Un) || Is(opCode, OpCodes.Blt_Un_S);

        private static string FormatComparisonExpression(OpCode opCode, CSharpExpression left, CSharpExpression right)
        {
            if (Is(opCode, OpCodes.Cgt_Un) && TryFormatReferenceNullInequality(left, right, out string referenceComparison))
                return referenceComparison;

            string comparison = GetComparisonOperator(opCode) ?? "==";
            string leftText = left.Text;
            string rightText = right.Text;

            if (left.Type?.IsEnum == true && IsIntegralLike(right.Type, right.Text))
                rightText = FormatExpressionForExpectedType(right, left.Type);
            else if (right.Type?.IsEnum == true && IsIntegralLike(left.Type, left.Text))
                leftText = FormatExpressionForExpectedType(left, right.Type);

            string prefix = IsUnsignedComparison(opCode) ? "/* unsigned */ " : string.Empty;
            return $"{prefix}({leftText} {comparison} {rightText})";
        }

        private static string FormatBranchComparisonExpression(OpCode opCode, CSharpExpression left, CSharpExpression right)
        {
            string comparison = GetBranchComparisonOperator(opCode) ?? "==";

            if (comparison == "!=" && TryFormatReferenceNullInequality(left, right, out string referenceComparison))
                return referenceComparison;

            string leftText = left.Text;
            string rightText = right.Text;

            if (left.Type?.IsEnum == true && IsIntegralLike(right.Type, right.Text))
                rightText = FormatExpressionForExpectedType(right, left.Type);
            else if (right.Type?.IsEnum == true && IsIntegralLike(left.Type, left.Text))
                leftText = FormatExpressionForExpectedType(left, right.Type);

            bool needsUnsignedMarker = IsUnsignedBranchComparison(opCode) && comparison is not "==" and not "!=";
            string prefix = needsUnsignedMarker ? "/* unsigned */ " : string.Empty;
            return $"{prefix}{leftText} {comparison} {rightText}";
        }

        private static bool TryFormatReferenceNullInequality(
            CSharpExpression left,
            CSharpExpression right,
            out string expression)
        {
            if (IsNullLiteral(right) && IsReferenceOrPointer(left.Type))
            {
                expression = $"({left.Text} != null)";
                return true;
            }

            if (IsNullLiteral(left) && IsReferenceOrPointer(right.Type))
            {
                expression = $"({right.Text} != null)";
                return true;
            }

            expression = string.Empty;
            return false;
        }

        private static bool IsNullLiteral(CSharpExpression expression) =>
            string.Equals(expression.Text, "null", StringComparison.Ordinal);

        private static bool IsReferenceOrPointer(Type? type) =>
            type is not null && (!type.IsValueType || type.IsPointer);

        private static bool IsIntegralLike(Type? type, string text)
        {
            if (TryParseIntegerLiteral(text, out _))
                return true;

            if (type is null || type.IsEnum)
                return false;

            return type == typeof(byte) || type == typeof(sbyte) ||
                   type == typeof(short) || type == typeof(ushort) ||
                   type == typeof(int) || type == typeof(uint) ||
                   type == typeof(long) || type == typeof(ulong) ||
                   type == typeof(char) || type == typeof(IntPtr) || type == typeof(UIntPtr);
        }

        private static Type? GetConversionType(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Conv_I1) || Is(opCode, OpCodes.Conv_Ovf_I1) || Is(opCode, OpCodes.Conv_Ovf_I1_Un)) return typeof(sbyte);
            if (Is(opCode, OpCodes.Conv_U1) || Is(opCode, OpCodes.Conv_Ovf_U1) || Is(opCode, OpCodes.Conv_Ovf_U1_Un)) return typeof(byte);
            if (Is(opCode, OpCodes.Conv_I2) || Is(opCode, OpCodes.Conv_Ovf_I2) || Is(opCode, OpCodes.Conv_Ovf_I2_Un)) return typeof(short);
            if (Is(opCode, OpCodes.Conv_U2) || Is(opCode, OpCodes.Conv_Ovf_U2) || Is(opCode, OpCodes.Conv_Ovf_U2_Un)) return typeof(ushort);
            if (Is(opCode, OpCodes.Conv_I4) || Is(opCode, OpCodes.Conv_Ovf_I4) || Is(opCode, OpCodes.Conv_Ovf_I4_Un)) return typeof(int);
            if (Is(opCode, OpCodes.Conv_U4) || Is(opCode, OpCodes.Conv_Ovf_U4) || Is(opCode, OpCodes.Conv_Ovf_U4_Un)) return typeof(uint);
            if (Is(opCode, OpCodes.Conv_I8) || Is(opCode, OpCodes.Conv_Ovf_I8) || Is(opCode, OpCodes.Conv_Ovf_I8_Un)) return typeof(long);
            if (Is(opCode, OpCodes.Conv_U8) || Is(opCode, OpCodes.Conv_Ovf_U8) || Is(opCode, OpCodes.Conv_Ovf_U8_Un)) return typeof(ulong);
            if (Is(opCode, OpCodes.Conv_R4)) return typeof(float);
            if (Is(opCode, OpCodes.Conv_R8) || Is(opCode, OpCodes.Conv_R_Un)) return typeof(double);
            if (Is(opCode, OpCodes.Conv_I) || Is(opCode, OpCodes.Conv_Ovf_I) || Is(opCode, OpCodes.Conv_Ovf_I_Un)) return typeof(IntPtr);
            if (Is(opCode, OpCodes.Conv_U) || Is(opCode, OpCodes.Conv_Ovf_U) || Is(opCode, OpCodes.Conv_Ovf_U_Un)) return typeof(UIntPtr);
            return null;
        }

        private static bool IsOverflowCheckedConversion(OpCode opCode) => opCode.Name?.StartsWith("conv.ovf.", StringComparison.Ordinal) == true;

        private static bool IsUnsignedConversion(OpCode opCode) => opCode.Name?.EndsWith(".un", StringComparison.Ordinal) == true;

        private static bool IsFieldInstruction(OpCode opCode) =>
            Is(opCode, OpCodes.Ldfld) || Is(opCode, OpCodes.Ldflda) || Is(opCode, OpCodes.Stfld) ||
            Is(opCode, OpCodes.Ldsfld) || Is(opCode, OpCodes.Ldsflda) || Is(opCode, OpCodes.Stsfld);

        private static bool IsLoadElement(OpCode opCode) =>
            Is(opCode, OpCodes.Ldelem) || Is(opCode, OpCodes.Ldelem_I) || Is(opCode, OpCodes.Ldelem_I1) ||
            Is(opCode, OpCodes.Ldelem_I2) || Is(opCode, OpCodes.Ldelem_I4) || Is(opCode, OpCodes.Ldelem_I8) ||
            Is(opCode, OpCodes.Ldelem_U1) || Is(opCode, OpCodes.Ldelem_U2) || Is(opCode, OpCodes.Ldelem_U4) ||
            Is(opCode, OpCodes.Ldelem_R4) || Is(opCode, OpCodes.Ldelem_R8) || Is(opCode, OpCodes.Ldelem_Ref);

        private static bool IsStoreElement(OpCode opCode) =>
            Is(opCode, OpCodes.Stelem) || Is(opCode, OpCodes.Stelem_I) || Is(opCode, OpCodes.Stelem_I1) ||
            Is(opCode, OpCodes.Stelem_I2) || Is(opCode, OpCodes.Stelem_I4) || Is(opCode, OpCodes.Stelem_I8) ||
            Is(opCode, OpCodes.Stelem_R4) || Is(opCode, OpCodes.Stelem_R8) || Is(opCode, OpCodes.Stelem_Ref);

        private static Type? GetElementTypeFromLoad(in JitIlInstruction instruction, Type? arrayType)
        {
            if (Is(instruction.OpCode, OpCodes.Ldelem)) return GetResolvedType(in instruction);
            if (Is(instruction.OpCode, OpCodes.Ldelem_I1)) return typeof(sbyte);
            if (Is(instruction.OpCode, OpCodes.Ldelem_U1)) return typeof(byte);
            if (Is(instruction.OpCode, OpCodes.Ldelem_I2)) return typeof(short);
            if (Is(instruction.OpCode, OpCodes.Ldelem_U2)) return typeof(ushort);
            if (Is(instruction.OpCode, OpCodes.Ldelem_I4)) return typeof(int);
            if (Is(instruction.OpCode, OpCodes.Ldelem_U4)) return typeof(uint);
            if (Is(instruction.OpCode, OpCodes.Ldelem_I8)) return typeof(long);
            if (Is(instruction.OpCode, OpCodes.Ldelem_I)) return typeof(IntPtr);
            if (Is(instruction.OpCode, OpCodes.Ldelem_R4)) return typeof(float);
            if (Is(instruction.OpCode, OpCodes.Ldelem_R8)) return typeof(double);
            if (Is(instruction.OpCode, OpCodes.Ldelem_Ref)) return arrayType?.GetElementType() ?? typeof(object);
            return arrayType?.GetElementType();
        }

        private static Type? GetIndirectLoadType(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Ldind_I1)) return typeof(sbyte);
            if (Is(opCode, OpCodes.Ldind_U1)) return typeof(byte);
            if (Is(opCode, OpCodes.Ldind_I2)) return typeof(short);
            if (Is(opCode, OpCodes.Ldind_U2)) return typeof(ushort);
            if (Is(opCode, OpCodes.Ldind_I4)) return typeof(int);
            if (Is(opCode, OpCodes.Ldind_U4)) return typeof(uint);
            if (Is(opCode, OpCodes.Ldind_I8)) return typeof(long);
            if (Is(opCode, OpCodes.Ldind_I)) return typeof(IntPtr);
            if (Is(opCode, OpCodes.Ldind_R4)) return typeof(float);
            if (Is(opCode, OpCodes.Ldind_R8)) return typeof(double);
            if (Is(opCode, OpCodes.Ldind_Ref)) return typeof(object);
            return null;
        }

        private static Type? GetIndirectStoreType(OpCode opCode)
        {
            if (Is(opCode, OpCodes.Stind_I1)) return typeof(sbyte);
            if (Is(opCode, OpCodes.Stind_I2)) return typeof(short);
            if (Is(opCode, OpCodes.Stind_I4)) return typeof(int);
            if (Is(opCode, OpCodes.Stind_I8)) return typeof(long);
            if (Is(opCode, OpCodes.Stind_I)) return typeof(IntPtr);
            if (Is(opCode, OpCodes.Stind_R4)) return typeof(float);
            if (Is(opCode, OpCodes.Stind_R8)) return typeof(double);
            if (Is(opCode, OpCodes.Stind_Ref)) return typeof(object);
            return null;
        }

        private static Type? DetermineMergeType(CSharpExpression left, CSharpExpression right)
        {
            if (left.Type == right.Type)
                return left.Type;
            if (left.Type == typeof(bool) && IsBooleanIntegralLiteral(right.Text))
                return typeof(bool);
            if (right.Type == typeof(bool) && IsBooleanIntegralLiteral(left.Text))
                return typeof(bool);
            return left.Type ?? right.Type;
        }

        private static string FormatExpressionForExpectedType(CSharpExpression expression, Type? expectedType)
        {
            if (expectedType is null)
                return expression.Text;

            if (expectedType.IsByRef)
                expectedType = expectedType.GetElementType() ?? expectedType;

            Type? nullableUnderlying = Nullable.GetUnderlyingType(expectedType);
            if (nullableUnderlying is not null)
                expectedType = nullableUnderlying;

            if (expectedType == typeof(bool))
            {
                if (string.Equals(expression.Text, "0", StringComparison.Ordinal))
                    return "false";
                if (string.Equals(expression.Text, "1", StringComparison.Ordinal))
                    return "true";
            }

            if (expectedType.IsEnum && TryParseIntegerLiteral(expression.Text, out long enumValue))
            {
                try
                {
                    object boxed = Enum.ToObject(expectedType, enumValue);
                    string? name = Enum.GetName(expectedType, boxed);
                    if (!string.IsNullOrEmpty(name))
                        return FormatType(expectedType) + "." + EscapeIdentifier(name);
                }
                catch
                {
                }

                return "(" + FormatType(expectedType) + ")" + expression.Text;
            }

            return expression.Text;
        }

        private static bool IsBooleanIntegralLiteral(string text) =>
            string.Equals(text, "0", StringComparison.Ordinal) || string.Equals(text, "1", StringComparison.Ordinal);

        private static bool TryParseIntegerLiteral(string text, out long value)
        {
            string candidate = text.Trim();
            if (candidate.EndsWith("L", StringComparison.OrdinalIgnoreCase))
                candidate = candidate.Substring(0, candidate.Length - 1);
            return long.TryParse(candidate, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
        }

        private static string FormatTruthTest(CSharpExpression condition, bool branchWhenTrue)
        {
            string test;
            Type? type = condition.Type;
            if (type == typeof(bool))
            {
                test = condition.Text;
            }
            else if (type is not null && (!type.IsValueType || type.IsPointer))
            {
                test = $"{condition.Text} != null";
            }
            else if (type is not null && (type.IsPrimitive || type.IsEnum || type == typeof(IntPtr) || type == typeof(UIntPtr)))
            {
                test = $"{condition.Text} != 0";
            }
            else
            {
                test = $"/* IL truth test */ ({condition.Text})";
            }

            return branchWhenTrue ? test : $"!({test})";
        }

        private static string ParenthesizeTarget(string target)
        {
            if (target == "this" || IsSimpleIdentifierOrMember(target))
                return target;
            return "(" + target + ")";
        }

        private static bool IsSimpleIdentifierOrMember(string text)
        {
            if (string.IsNullOrEmpty(text))
                return false;

            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (!(char.IsLetterOrDigit(c) || c == '_' || c == '@' || c == '.'))
                    return false;
            }
            return true;
        }

        private static string FormatLabel(int offset) => "IL_" + offset.ToString("X4");

        private static bool IsBranchOperand(OpCode opCode) =>
            opCode.OperandType == OperandType.InlineBrTarget || opCode.OperandType == OperandType.ShortInlineBrTarget;

        private static string FormatMethodReference(MethodBase method)
        {
            string owner = FormatType(method.DeclaringType ?? typeof(object));
            return owner + "." + EscapeIdentifier(method.Name);
        }

        private static string FormatFieldReference(FieldInfo field)
        {
            string owner = FormatType(field.DeclaringType ?? typeof(object));
            return owner + "." + EscapeIdentifier(field.Name);
        }

        private static string FormatVisibility(MethodBase method)
        {
            if (method.IsPublic) return "public";
            if (method.IsFamilyOrAssembly) return "protected internal";
            if (method.IsFamilyAndAssembly) return "private protected";
            if (method.IsFamily) return "protected";
            if (method.IsAssembly) return "internal";
            return "private";
        }

        private static string GetParameterName(ParameterInfo parameter, int index)
        {
            string? name = parameter.Name;
            return string.IsNullOrEmpty(name) ? "arg" + index.ToString(CultureInfo.InvariantCulture) : name;
        }

        private static string FormatType(Type type)
        {
            if (TypeAliases.TryGetValue(type, out string? alias))
                return alias;

            if (type.IsByRef)
                return FormatType(type.GetElementType() ?? type);

            if (type.IsPointer)
                return FormatType(type.GetElementType() ?? typeof(void)) + "*";

            if (type.IsArray)
            {
                Type elementType = type.GetElementType() ?? typeof(object);
                int rank = type.GetArrayRank();
                return FormatType(elementType) + "[" + new string(',', Math.Max(0, rank - 1)) + "]";
            }

            if (type.IsGenericParameter)
                return EscapeIdentifier(type.Name);

            if (type.IsGenericType)
            {
                Type genericDefinition = type.GetGenericTypeDefinition();
                if (genericDefinition == typeof(Nullable<>))
                    return FormatType(type.GetGenericArguments()[0]) + "?";

                string name = GetNonGenericTypeName(type);
                Type[] arguments = type.GetGenericArguments();
                StringBuilder text = new();
                text.Append(name).Append('<');
                for (int i = 0; i < arguments.Length; i++)
                {
                    if (i != 0)
                        text.Append(", ");
                    text.Append(FormatType(arguments[i]));
                }
                return text.Append('>').ToString();
            }

            return (type.FullName ?? type.Name).Replace('+', '.');
        }

        private static string FormatSimpleTypeName(Type type)
        {
            if (TypeAliases.TryGetValue(type, out string? alias))
                return alias;

            string name = type.Name;
            int tick = name.IndexOf('`');
            if (tick >= 0)
                name = name.Substring(0, tick);
            return EscapeIdentifier(name);
        }

        private static string GetNonGenericTypeName(Type type)
        {
            string fullName = (type.FullName ?? type.Name).Replace('+', '.');
            int tick = fullName.IndexOf('`');
            return tick >= 0 ? fullName.Substring(0, tick) : fullName;
        }

        private static string EscapeIdentifier(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
                return "_";

            string sanitized = identifier;
            bool needsSanitizing = false;
            for (int i = 0; i < sanitized.Length; i++)
            {
                char c = sanitized[i];
                if (i == 0 ? !(char.IsLetter(c) || c == '_') : !(char.IsLetterOrDigit(c) || c == '_'))
                {
                    needsSanitizing = true;
                    break;
                }
            }

            if (needsSanitizing)
            {
                StringBuilder text = new(sanitized.Length + 1);
                for (int i = 0; i < sanitized.Length; i++)
                {
                    char c = sanitized[i];
                    bool valid = i == 0 ? char.IsLetter(c) || c == '_' : char.IsLetterOrDigit(c) || c == '_';
                    text.Append(valid ? c : '_');
                }
                sanitized = text.ToString();
            }

            return CSharpKeywords.Contains(sanitized) ? "@" + sanitized : sanitized;
        }

        private static string FormatSingle(float value)
        {
            if (float.IsNaN(value)) return "float.NaN";
            if (float.IsPositiveInfinity(value)) return "float.PositiveInfinity";
            if (float.IsNegativeInfinity(value)) return "float.NegativeInfinity";
            return value.ToString("R", CultureInfo.InvariantCulture) + "f";
        }

        private static string FormatDouble(double value)
        {
            if (double.IsNaN(value)) return "double.NaN";
            if (double.IsPositiveInfinity(value)) return "double.PositiveInfinity";
            if (double.IsNegativeInfinity(value)) return "double.NegativeInfinity";
            return value.ToString("R", CultureInfo.InvariantCulture) + "d";
        }

        private static int GetFixedPopCount(StackBehaviour behaviour)
        {
            return behaviour switch
            {
                StackBehaviour.Pop0 => 0,
                StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
                StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or
                    StackBehaviour.Popi_popi8 or StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or
                    StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
                StackBehaviour.Popi_popi_popi or StackBehaviour.Popref_popi_pop1 or StackBehaviour.Popref_popi_popi or
                    StackBehaviour.Popref_popi_popi8 or StackBehaviour.Popref_popi_popr4 or StackBehaviour.Popref_popi_popr8 or
                    StackBehaviour.Popref_popi_popref => 3,
                StackBehaviour.Varpop => -1,
                _ => -1
            };
        }

        private static int GetFixedPushCount(StackBehaviour behaviour)
        {
            return behaviour switch
            {
                StackBehaviour.Push0 => 0,
                StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or StackBehaviour.Pushr4 or
                    StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
                StackBehaviour.Push1_push1 => 2,
                StackBehaviour.Varpush => -1,
                _ => -1
            };
        }

        private static FrozenDictionary<Type, string> BuildTypeAliases()
        {
            Dictionary<Type, string> aliases = new()
            {
                [typeof(void)] = "void",
                [typeof(bool)] = "bool",
                [typeof(byte)] = "byte",
                [typeof(sbyte)] = "sbyte",
                [typeof(short)] = "short",
                [typeof(ushort)] = "ushort",
                [typeof(int)] = "int",
                [typeof(uint)] = "uint",
                [typeof(long)] = "long",
                [typeof(ulong)] = "ulong",
                [typeof(char)] = "char",
                [typeof(float)] = "float",
                [typeof(double)] = "double",
                [typeof(decimal)] = "decimal",
                [typeof(string)] = "string",
                [typeof(object)] = "object",
                [typeof(IntPtr)] = "nint",
                [typeof(UIntPtr)] = "nuint"
            };
            return aliases.ToFrozenDictionary();
        }

        private static FrozenSet<string> BuildKeywordSet()
        {
            string[] keywords =
            [
                "abstract", "as", "base", "bool", "break", "byte", "case", "catch", "char", "checked",
                "class", "const", "continue", "decimal", "default", "delegate", "do", "double", "else", "enum",
                "event", "explicit", "extern", "false", "finally", "fixed", "float", "for", "foreach", "goto",
                "if", "implicit", "in", "int", "interface", "internal", "is", "lock", "long", "namespace", "new",
                "null", "object", "operator", "out", "override", "params", "private", "protected", "public", "readonly",
                "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static", "string", "struct",
                "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort",
                "using", "virtual", "void", "volatile", "while", "add", "alias", "and", "ascending", "async", "await",
                "by", "descending", "dynamic", "equals", "file", "from", "get", "global", "group", "init", "into", "join",
                "let", "managed", "nameof", "nint", "not", "notnull", "nuint", "on", "or", "orderby", "partial", "record",
                "remove", "required", "scoped", "select", "set", "unmanaged", "value", "var", "when", "where", "with", "yield"
            ];
            return keywords.ToFrozenSet(StringComparer.Ordinal);
        }

        private static bool Is(OpCode left, OpCode right) => left.Value == right.Value;
    }
}
