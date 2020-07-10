﻿using PKISharp.WACS.Services;
using PKISharp.WACS.Services.Serialization;
using System;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.Interfaces
{
    public interface IPluginOptionsFactory
    {
        /// <summary>
        /// Unique identifier
        /// </summary>
        string? Name { get; }

        /// <summary>
        /// Check if name matches
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        bool Match(string name);

        /// <summary>
        /// Human-understandable description
        /// </summary>
        string? Description { get; }

        /// <summary>
        /// Which type is used as instance
        /// </summary>
        Type InstanceType { get; }

        /// <summary>
        /// Which type is used as options
        /// </summary>
        Type OptionsType { get; }

        /// <summary>
        /// How its sorted in the menu
        /// </summary>
        int Order { get; }

        /// <summary>
        /// Indicates whether the plugin is currently disabled and why
        /// </summary>
        /// <returns></returns>
        (bool, string?) Disabled { get; }
    }

    public interface IPluginOptionsFactory<T>: IPluginOptionsFactory where T: PluginOptions
    {
        /// <summary>
        /// Check or get configuration information needed (interactive)
        /// </summary>
        /// <param name="target"></param>
        Task<T?> Aquire(IInputService inputService, RunLevel runLevel);

        /// <summary>
        /// Check information needed (unattended)
        /// </summary>
        /// <param name="target"></param>
        Task<T?> Default();
    }

    public interface INull { }

    public interface IIgnore { }

    public interface IPlugin
    {
        /// <summary>
        /// Indicates whether the plugin is currently disabled and why
        /// </summary>
        /// <returns></returns>
        (bool, string?) Disabled { get; }
    }

}
