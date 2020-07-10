﻿using PKISharp.WACS.Clients.IIS;
using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Extensions;
using PKISharp.WACS.Services;
using System.Threading.Tasks;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Http
{
    /// <summary>
    /// Classic FileSystem validation
    /// </summary>
    internal class FileSystemOptionsFactory : HttpValidationOptionsFactory<FileSystem, FileSystemOptions>
    {
        private readonly IIISClient _iisClient;
        private readonly ILogService _log;

        public FileSystemOptionsFactory(
            IIISClient iisClient, ILogService log,
            IArgumentsService arguments) : base(arguments)
        {
            _log = log;
            _iisClient = iisClient;
        }

        public override bool PathIsValid(string path) => path.ValidPath(_log);
        public override bool AllowEmtpy(Target target) => target.IIS;

        public override async Task<FileSystemOptions?> Default(Target target)
        {
            var args = _arguments.GetArguments<FileSystemArguments>();
            var ret = new FileSystemOptions(BaseDefault(target));
            if (target.IIS && _iisClient.HasWebSites)
            {

                if (args?.ValidationSiteId != null)
                {
                    // Throws exception when not found
                    var site = _iisClient.GetWebSite(args.ValidationSiteId.Value);
                    ret.Path = site.Path;
                    ret.SiteId = args.ValidationSiteId.Value;
                }
            }
            return ret;
        }

        public override async Task<FileSystemOptions?> Aquire(Target target, IInputService inputService, RunLevel runLevel)
        {
            // Choose alternative site for validation
            var ret = new FileSystemOptions(await BaseAquire(target, inputService));
            if (target.IIS && _iisClient.HasWebSites && string.IsNullOrEmpty(ret.Path))
            {
                if (await inputService.PromptYesNo("Use different site for validation?", false))
                {
                    var site = await inputService.ChooseOptional("Validation site, must receive requests for all hosts on port 80",
                        _iisClient.WebSites,
                        x => Choice.Create<IIISSite?>(x, x.Name, x.Id.ToString()),
                        "Automatic (target site)");
                    if (site != null)
                    {
                        ret.Path = site.Path;
                        ret.SiteId = site.Id;
                    }
                }
            }
            return ret;
        }
    }

}
