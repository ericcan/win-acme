﻿using PKISharp.WACS.Extensions;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.TargetPlugins
{
    internal class CsrOptionsFactory : TargetPluginOptionsFactory<Csr, CsrOptions>
    {
        private readonly ILogService _log;
        private readonly IArgumentsService _arguments;

        public CsrOptionsFactory(ILogService log, IArgumentsService arguments)
        {
            _log = log;
            _arguments = arguments;
        }

        public override int Order => 6;

        public override async Task<CsrOptions?> Aquire(IInputService inputService, RunLevel runLevel)
        {
            var args = _arguments.GetArguments<CsrArguments>();
            var ret = new CsrOptions();
            do
            {
                ret.CsrFile = await _arguments.TryGetArgument(
                    args?.CsrFile,
                    inputService,
                    "Enter the path to the CSR");
            }
            while (!ret.CsrFile.ValidFile(_log));

            string? pkFile;
            do
            {
                pkFile = await _arguments.TryGetArgument(args?.CsrFile,
                    inputService,
                    "Enter the path to the corresponding private key, or <Enter> to create a certificate without one");
            }
            while (!(string.IsNullOrWhiteSpace(pkFile) || pkFile.ValidFile(_log)));

            if (!string.IsNullOrWhiteSpace(pkFile))
            {
                ret.PkFile = pkFile;
            }

            return ret;
        }

        public override async Task<CsrOptions?> Default()
        {
            var args = _arguments.GetArguments<CsrArguments>();
            if (!args?.CsrFile.ValidFile(_log) ?? false)
            {
                return null;
            }
            if (!string.IsNullOrEmpty(args?.PkFile))
            {
                if (!args.PkFile.ValidFile(_log))
                {
                    return null;
                }
            }
            return new CsrOptions()
            {
                CsrFile = args?.CsrFile,
                PkFile = string.IsNullOrWhiteSpace(args?.PkFile) ? null : args.PkFile
            };
        }
    }
}
