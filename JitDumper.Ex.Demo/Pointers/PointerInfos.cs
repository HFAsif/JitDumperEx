using Microsoft.Extensions.Logging;

namespace LoaderExDemo
{
    [HelperClass.SomeElementsInfos("Selects CLR and architecture pointer resolver.")]
    internal sealed class PointerInfos : PointerInfosBase
    {


        [HelperClass.SomeElementsInfos("Resolves CLR execution entry pointers.")]
        public bool Resolve()
        {
            ClearPointers();

            return RuntimeKey switch
            {
                42 => PointerInfosNetTwoExThirtyTwo.Resolve(this),
                44 => PointerInfosNetFourExThirtyTwo.Resolve(this),
                82 => PointerInfosNetTwoExSixtyFour.Resolve(this),
                84 => PointerInfosNetFourExSixtyFour.Resolve(this),
                _ => throw new NotSupportedException("Unsupported CLR/architecture combination. RuntimeKey=" + RuntimeKey)
            };
        }

        public void Print()
        {
            ILogger logger = ThisStaticClass.Logger;
            if (!logger.IsEnabled(LogLevel.Information))
                return;

            logger.LogInformation("[PointerInfos RuntimeKey={RuntimeKey}]", RuntimeKey);
            logger.LogInformation("_CorDllMain = {Address}", FormatPointer(CorDllMain));
            logger.LogInformation("ExecuteDLL CALL = {Address}", FormatPointer(ExecuteDLLCall));
            logger.LogInformation("ExecuteDLL = {Address}", FormatPointer(ExecuteDLL));
            logger.LogInformation("ExecuteDLLForAttach CALL = {Address}", FormatPointer(ExecuteDLLForAttachCall));
            logger.LogInformation("ExecuteDLLForAttach = {Address}", FormatPointer(ExecuteDLLForAttach));
            logger.LogInformation("_CorExeMain = {Address}", FormatPointer(CorExeMain));
            logger.LogInformation("_CorExeMainInternal CALL = {Address}", FormatPointer(CorExeMainInternalCall));
            logger.LogInformation("_CorExeMainInternal = {Address}", FormatPointer(CorExeMainInternal));
            logger.LogInformation("ExecuteEXE CALL = {Address}", FormatPointer(ExecuteEXECall));
            logger.LogInformation("ExecuteEXE = {Address}", FormatPointer(ExecuteEXE));
        }

        private static string FormatPointer(IntPtr pointer) => "0x" + pointer.ToInt64().ToString(IntPtr.Size == 8 ? "X16" : "X8");
    }
}
