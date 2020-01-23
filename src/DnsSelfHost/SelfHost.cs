using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Services;
using DNS.Server.Acme;
using System.Linq;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class SelfDNS : DnsValidation<SelfDNS>
    {
        private DnsServerAcme selfDnsServer;
        public SelfDNS(
            LookupClientProvider dnsClient,
            ILogService log, 
            ISettingsService settings,
            SelfDNSOptions options, string
            identifier) :
            base(dnsClient, log, settings)
        {
        }
        public override async Task PrepareChallenge()
        {
            //setup for temporary DNS Server
            selfDnsServer = new DnsServerAcme(_log);

            await CreateRecord(Challenge.DnsRecordName, Challenge.DnsRecordValue);
            selfDnsServer.Listen();

            PreValidate();
        }
        public override async Task CreateRecord(string recordName, string token)
        {
           selfDnsServer.AddRecord(recordName, token);
            _log.Information("Validation TXT {token} added to DNS Server {answerUri}", token, recordName);
        }
        public override async Task DeleteRecord(string recordName, string token)
        {          
        }
        public override async Task CleanUp()
        {
            selfDnsServer.Dispose();
            await base.CleanUp();
        }
        protected new bool PreValidate()
        {
            try
            {
                LookupClientWrapper dnsClient;

                dnsClient = _dnsClientProvider.GetDefaultClient(0);

                var tokens =  dnsClient.GetTextRecordValues(Challenge.DnsRecordName,0).Result;
                if (tokens.Contains(Challenge.DnsRecordValue))
                {
                    _log.Information("Preliminary validation succeeded: {ExpectedTxtRecord} found in {TxtRecords}", Challenge.DnsRecordValue, String.Join(", ", tokens));
                    return true;
                }
                else if (!tokens.Any())
                {
                    _log.Warning("Preliminary validation failed: no TXT records found");
                }
                else
                {
                    _log.Warning("Preliminary validation failed: {ExpectedTxtRecord} not found in {TxtRecords}", Challenge.DnsRecordValue, String.Join(", ", tokens));
                }
            }
            catch
            {
                _log.Error("Preliminary validation failed");
            }
            return false;
        }
    }
}
