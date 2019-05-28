using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNSOptionsFactory : ValidationPluginOptionsFactory<SelfDNS, SelfDNSOptions>
    {
        public SelfDNSOptionsFactory(ILogService log) : base(log, Constants.Dns01ChallengeType) { }

        public override SelfDNSOptions Aquire(Target target, IArgumentsService arguments, IInputService inputService, RunLevel runLevel)
        {
            return new SelfDNSOptions();
        }

        public override SelfDNSOptions Default(Target target, IArgumentsService arguments)
        {
            return new SelfDNSOptions();
        }

        public override bool CanValidate(Target target)
        {
            return true;
        }
    }
}
