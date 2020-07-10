﻿using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Options;
using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.Base.Factories.Null
{
    /// <summary>
    /// Null implementation
    /// </summary>
    internal class NullInstallationOptionsFactory : IInstallationPluginOptionsFactory, INull
    {
        Type IPluginOptionsFactory.InstanceType => typeof(NullInstallation);
        Type IPluginOptionsFactory.OptionsType => typeof(NullInstallationOptions);
        Task<InstallationPluginOptions> Generate() => Task.FromResult<InstallationPluginOptions>(new NullInstallationOptions());
        Task<InstallationPluginOptions> IInstallationPluginOptionsFactory.Aquire(Target target, IInputService inputService, RunLevel runLevel) => Generate();
        Task<InstallationPluginOptions> IInstallationPluginOptionsFactory.Default(Target target) => Generate();
        bool IInstallationPluginOptionsFactory.CanInstall(IEnumerable<Type> storeTypes) => true;
        int IPluginOptionsFactory.Order => int.MaxValue;
        (bool, string?) IPluginOptionsFactory.Disabled => (false, null);
        string IPluginOptionsFactory.Name => new NullInstallationOptions().Name;
        string IPluginOptionsFactory.Description => new NullInstallationOptions().Description;
        bool IPluginOptionsFactory.Match(string name) => string.Equals(name, new NullInstallationOptions().Name, StringComparison.CurrentCultureIgnoreCase);
    }

    [Plugin("aecc502c-5f75-43d2-b578-f95d50c79ea1")]
    internal class NullInstallationOptions : InstallationPluginOptions<NullInstallation>
    {
        public override string Name => "None";
        public override string Description => "No (additional) installation steps";
    }

    internal class NullInstallation : IInstallationPlugin
    {
        (bool, string?) IPlugin.Disabled => (false, null);
        Task IInstallationPlugin.Install(Target target, IEnumerable<IStorePlugin> stores, CertificateInfo newCertificateInfo, CertificateInfo? oldCertificateInfo) => Task.CompletedTask;
    }
}
