using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Services;
using System.Linq;
using System;
using System.Net;
using DNS.Server.Acme;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNS : DnsValidation<SelfDNSOptions, SelfDNS>
    {
        private DnsServerAcme selfDnsServer;
        public SelfDNS(
            LookupClientProvider dnsClient,
            ILogService log,
            SelfDNSOptions options, string
            identifier) :
            base(dnsClient, log, options, identifier)
        {
        }
        public override void PrepareChallenge()
        {
            //setup for temporary DNS Server
            selfDnsServer = new DnsServerAcme(_log);

            CreateRecord(_challenge.DnsRecordName, _challenge.DnsRecordValue);
            selfDnsServer.Listen();

            PreValidate();
        }
        public override void CreateRecord(string recordName, string token)
        {
           selfDnsServer.AddRecord(recordName, token);
            _log.Information("Validation TXT {token} added to DNS Server {answerUri}", token, recordName);
        }
        public override void DeleteRecord(string recordName, string token)
        {          
        }
        public override void CleanUp()
        {
            selfDnsServer.Dispose();
            base.CleanUp();
        }
        protected new bool PreValidate()
        {
            try
            {
                LookupClientWrapper dnsClient;
                if (IPAddress.TryParse(Properties.Settings.Default.DnsServer, out IPAddress overrideNameServerIp))
                {
                    dnsClient = _dnsClientProvider.GetClient(overrideNameServerIp);
                }
                else
                {
                    dnsClient = _dnsClientProvider.DefaultClient;
                }
                var tokens = dnsClient.GetTextRecordValues(_challenge.DnsRecordName).ToList();
                if (tokens.Contains(_challenge.DnsRecordValue))
                {
                    _log.Information("Preliminary validation succeeded: {ExpectedTxtRecord} found in {TxtRecords}", _challenge.DnsRecordValue, String.Join(", ", tokens));
                    return true;
                }
                else if (!tokens.Any())
                {
                    _log.Warning("Preliminary validation failed: no TXT records found");
                }
                else
                {
                    _log.Warning("Preliminary validation failed: {ExpectedTxtRecord} not found in {TxtRecords}", _challenge.DnsRecordValue, String.Join(", ", tokens));
                }
            }
            catch (Exception ex)
            {
                _log.Error(ex, "Preliminary validation failed");
            }
            return false;
        }

    }
}
