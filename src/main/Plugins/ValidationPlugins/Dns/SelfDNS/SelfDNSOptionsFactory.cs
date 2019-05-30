using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;
using PKISharp.WACS.Clients.DNS;
using DNS.Server;
using System.Net;
using System.Linq;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNSOptionsFactory : ValidationPluginOptionsFactory<SelfDNS, SelfDNSOptions>
    {
        private readonly LookupClientProvider _dnsClient;
        private readonly IInputService _input;
        private MasterFile testDNSRecords;
        private DnsServer server;
        private bool _reqReceived;

        public SelfDNSOptionsFactory( ILogService log, LookupClientProvider dnsClient,
            IInputService input) : base(log, Constants.Dns01ChallengeType) {
            _dnsClient = dnsClient;
            _input = input;
 
            testDNSRecords = new MasterFile();
            server = new DnsServer(testDNSRecords, "8.8.8.8");
            server.Responded += (sender, e) =>
            {
                _reqReceived = true;
                _log.Information("DNS Server received lookup request from {remote}", e.Remote.Address.ToString());
                _log.Debug("DNS Request: " + e.Request.ToString());
                _log.Debug("DNS Response: " + e.Response.ToString());
            };
        }

        public override SelfDNSOptions Aquire(Target target, IArgumentsService arguments, IInputService inputService, RunLevel runLevel)
        {
            //start by pre-checking to see whether lookup works by starting a server
            //and then doing a lookup for a test record or just seeing whether the event fires.
            var testDomain = "_acme-challenge.testdomain.org";
            var testTXT = "custom TXTrecord";
            testDNSRecords.AddTextResourceRecord(testDomain, "", testTXT);
            server.Listen();
            string testResponse = "";

            var identifiers = target.Parts.SelectMany(x => x.Identifiers);
            identifiers = identifiers.Select( x  =>  x.Replace("*.", "")  ).Distinct();
            identifiers = identifiers.Select(x => x="_acme-challenge."+x);
            _log.Information("To set up self-hosted DNS validation, ensure the following:");
            _log.Information("--You have opened port 53 in your firewall for incoming requests");
            _log.Information("--You have created the following records with your domain host's DNS manager:");
            foreach (var identifier in identifiers)
            {
                _input.Show("NS", identifier);
            }
            _log.Information("Each NS record should point to this server's name (you will need to create an A record for this server)");
            IPAddress serverIP;
            while (true)
            {
                try
                {

                string externalip = new WebClient().DownloadString("http://icanhazip.com").Replace("\n","");
                serverIP = IPAddress.Parse(externalip);

                _log.Information("Checking that port 53 is open on {IP}...",externalip);
                 testResponse = _dnsClient.GetClient(serverIP).GetTextRecordValues(testDomain).First();
            }
            catch { }
                if (testResponse == testTXT)
                {
                    _log.Information("Port 53 appears to be open and the DNS server is operating correctly");
                    break;
                }
                else
                {
                   if(! _input.PromptYesNo("The DNS server is not exposed on port 53. Would you like to try again?",false) ){
                        break;
                    }
                }
            }
            while (true)
            {
                int failCount=identifiers.Count();
                foreach (var identifier in identifiers)
                {
                    _reqReceived = false;
                    testDNSRecords.AddTextResourceRecord(identifier, "", testTXT);
                    _log.Information("Checking NS record setup for {identifier}", identifier);
                    var TXTRes = _dnsClient.DefaultClient.GetTextRecordValues(identifier);
                    if (TXTRes.Contains(testTXT))
                    {
                        _log.Information("Found {identifier}", identifier);
                        failCount -= 1;
                    }
                    else if (TXTRes.Any())
                    {
                        _log.Warning("TXT record found for {identifier} but it appears to coming from a different DNS server. Check the NS record", identifier);
                    }
                    else if (_reqReceived)
                    {
                        _log.Warning("A DNS request was received but may have the wrong domain name. Check your NS record");
                    }
                    else
                    {
                        _log.Warning("No request was received by the DNS server");
                    }
                }
                if (failCount == 0) break;
                if (!_input.PromptYesNo("Would you like to test the DNS entries again?",false)) break;
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
