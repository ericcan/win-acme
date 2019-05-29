using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;
using PKISharp.WACS.Clients.DNS;
using DNS.Server;
using System.Linq;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNSOptionsFactory : ValidationPluginOptionsFactory<SelfDNS, SelfDNSOptions>
    {
        private readonly LookupClientProvider _dnsClient;
        private readonly IInputService _input;
        private MasterFile testDNSRecords;
        private DnsServer server;

        public SelfDNSOptionsFactory(ILogService log, LookupClientProvider dnsClient,
            IInputService input) : base(log, Constants.Dns01ChallengeType) {
            _dnsClient = dnsClient;
            _input = input;

            testDNSRecords = new MasterFile();
            server = new DnsServer(testDNSRecords, "8.8.8.8");
            server.Responded += (sender, e) =>
            {
                _log.Information("DNS Server received lookup request from {remote}", e.Remote.Address.ToString());
                _log.Debug("DNS Request: " + e.Request.ToString());
                _log.Debug("DNS Response: " + e.Response.ToString());
            };
        }

        public override SelfDNSOptions Aquire(Target target, IArgumentsService arguments, IInputService inputService, RunLevel runLevel)
        {
            //start by pre-checking to see whether lookup works by starting a server
            //and then doing a lookup for a test record or just seeing whether the event fires.
            testDNSRecords.AddTextResourceRecord("_acme-challenge.testdomain.org", "", "custom TXTrecord");
            server.Listen();
            var testResponse = _dnsClient.DefaultClient.GetTextRecordValues("_acme-challenge.testdomain.org").First();
            if (testResponse == "custom TXTrecord")
            {
                _log.Information("Port 53 appears to be opened correctly");
            } else { 
                //if the port appears to be open, then check the each of the targets to make sure that the specific
                //identifiers are set up by adding records for each and making sure that they produce results.

                //if these tests don't yield results, tell user to set up
                _log.Information("To set up self-hosted DNS validation, insure the following:");
                _log.Information("--You have opened port 53 in your firewall for incoming requests");
                _log.Information("--You have created a NS DNS record for _acme-challenge...., pointing to your server's web address");
                _log.Information("To test your setup, port 53 is now open and you may perform a TXT query for");
                _log.Information("_acme-challenge.testdomain.org, specifying your server as the DNS Server.");
                _log.Information(" You should get a TXT value of 'custom TXTrecord'");

                _input.Wait("Press ENTER once you have opened the port.\n");
            }
            server.Dispose();
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
