using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;

namespace Crypto_Tool
{
    /// <summary>
    /// App.xaml 的交互逻辑
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                //string resourceName = "FileCrypt.dll." + new AssemblyName(args.Name).Name + ".dll";
                string dllName = new AssemblyName(args.Name).Name + ".dll";
                var assm = Assembly.GetExecutingAssembly();
                var resourceName = assm.GetManifestResourceNames().FirstOrDefault(rn => rn.EndsWith(dllName));
                if (resourceName == null)
                {
                    return null;
                }
                using (var stream = assm.GetManifestResourceStream(resourceName))
                {
                    byte[] assemblyData = new byte[stream.Length];
                    stream.Read(assemblyData, 0, assemblyData.Length);
                    return Assembly.Load(assemblyData);
                }
            };
            base.OnStartup(e);
        }
    }
}
