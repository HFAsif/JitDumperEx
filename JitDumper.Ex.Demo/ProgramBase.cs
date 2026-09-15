using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace LoaderExDemo
{
    internal class ProgramBase
    {
        protected static void OnProcessExit(object? sender, EventArgs e)
        {
            try
            {
                PrintSomeElementsInfos();
            }
            catch (Exception ex)
            {
                ThisStaticClass.Logger.LogInformation("[SomeElementsInfos] scan failed: " + ex.Message);
            }
        }

        [HelperClass.SomeElementsInfos("Prints annotated design notes on exit.")]
        protected static void PrintSomeElementsInfos()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            List<string> lines = new();

            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                List<Type> loadedTypes = new(ex.Types.Length);
                foreach (Type? type in ex.Types)
                {
                    if (type is not null)
                        loadedTypes.Add(type);
                }
                types = loadedTypes.ToArray();
            }

            foreach (Type type in types)
            {
                foreach (HelperClass.SomeElementsInfos info in type.GetCustomAttributes<HelperClass.SomeElementsInfos>(false))
                    lines.Add($"TYPE   {type.FullName ?? type.Name} => {info.Details}");

                const BindingFlags methodFlags = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
                foreach (MethodInfo method in type.GetMethods(methodFlags))
                {
                    foreach (HelperClass.SomeElementsInfos info in method.GetCustomAttributes<HelperClass.SomeElementsInfos>(false))
                        lines.Add($"METHOD {type.FullName ?? type.Name}::{method.Name} => {info.Details}");
                }
            }

            lines.Sort(StringComparer.Ordinal);
            ThisStaticClass.Logger.LogInformation(Environment.NewLine);
            ThisStaticClass.Logger.LogInformation(Environment.NewLine);
            ThisStaticClass.Logger.LogInformation("[SomeElementsInfos] " + assembly.GetName().Name);
            foreach (string line in lines)
                ThisStaticClass.Logger.LogInformation(line);
            ThisStaticClass.Logger.LogInformation("[SomeElementsInfos] Total=" + lines.Count);
        }
    }
}
