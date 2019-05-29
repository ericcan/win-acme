using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Services;
using System.Linq;
using System.Threading.Tasks;
using System;
using DNS.Server;
using DNS.Client;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNS : DnsValidation<SelfDNSOptions, SelfDNS>
    {
        private MasterFile masterFile;
        private DnsServer server;
        public SelfDNS(
            LookupClientProvider dnsClient,
            ILogService log,
            SelfDNSOptions options, string
            identifier) :
            base(dnsClient, log, options, identifier)
        {
            masterFile = new MasterFile();
            server = new DnsServer(masterFile, "8.8.8.8");
            server.Responded += (sender, e) => 
            {
                _log.Information("DNS Server received lookup request from {remote}", e.Remote.Address.ToString() );
                _log.Debug("DNS Request: " + e.Request.ToString());
                _log.Debug("DNS Response: " + e.Response.ToString());
            };
            server.Listening += (sender, e) => _log.Information("DNS Server is listening on Port 53. Make sure your firewall has opened this port");
            server.Errored += (sender, e) =>
            {
                _log.Debug("Errored: {Error}", e.Exception);
                ResponseException responseError = e.Exception as ResponseException;
                if (responseError != null) _log.Debug(responseError.Response.ToString());
            };
        }
        public override void PrepareChallenge()
        {
            CreateRecord(_challenge.DnsRecordName, _challenge.DnsRecordValue);
            _log.Information("Validation token added to DNS Server TXT for {answerUri}", _challenge.DnsRecordName);
            server.Listen();

            PreValidate(false);
        }
        public override void CreateRecord(string recordName, string token)
        {
            masterFile.AddTextResourceRecord(recordName, "", token);
            masterFile.AddNameServerResourceRecord(recordName, "aws.candell.org"); //need to replace with user parameter
        }
        public override void DeleteRecord(string recordName, string token)
        {
            server.Dispose();
            _log.Information("DNS Server terminated from Port 53");
        }

    }
}
