using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Plugins.Base.Factories;
using PKISharp.WACS.Services;
using PKISharp.WACS.Clients.DNS;
using DNS.Server;
using System.Net;
using System.Linq;
using System.Collections.Generic;

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
                var questions = e.Request.Questions;
                foreach (var question in questions)
                {
                    _log.Debug("DNS Request: " + question.ToString());
                }
                var answers = e.Response.AnswerRecords;
                foreach (var answer in answers)
                {
                    _log.Debug("DNS Response: " + answer.ToString());
                }
            };
        }

        public override SelfDNSOptions Aquire(Target target, IArgumentsService arguments, IInputService inputService, RunLevel runLevel)
        {
            //start by pre-checking to see whether lookup works by starting a server
            //and then doing a lookup for a test record or just seeing whether the event fires.

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
            //test for existence of an open port and working DNS server
            IPAddress serverIP=IPAddress.Parse("8.8.8.8");
            string externalip = "";
            try
            {
                externalip = new WebClient().DownloadString("http://icanhazip.com").Replace("\n", "");
                serverIP = IPAddress.Parse(externalip);
            }
            catch
            {
                _log.Error("couldn't get server's external IP address");
            }
            //publish a test record and query to see if it can be found
            var testDomain = "_acme-challenge.testdomain.org";
            var testTXT = "custom TXTrecord";
            testDNSRecords.AddTextResourceRecord(testDomain, "", testTXT);
            var testResponse = new List<string>();
            server.Listen();
            while (true)
            {


                _log.Information("Checking that port 53 is open on {IP}...",externalip);
                testResponse = _dnsClient.GetClient(serverIP).GetTextRecordValues(testDomain).ToList();
                if (testResponse.Any())
                {
                    if (testResponse.First() == testTXT)
                    {
                        _log.Information("Port 53 appears to be open and the DNS server is operating correctly");
                        break;
                    }
                }
                else
                {
                    if (!_input.PromptYesNo("The DNS server is not exposed on port 53. Would you like to try again?", false))
                    {
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
