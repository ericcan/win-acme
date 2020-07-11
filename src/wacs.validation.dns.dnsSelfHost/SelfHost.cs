using ACMESharp.Authorizations;
using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Services;
using PKISharp.WACS.Context;
using DNS.Server.Acme;
using System.Linq;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using static PKISharp.WACS.Clients.DNS.LookupClientProvider;

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
        public override async Task PrepareChallenge(ValidationContext context, Dns01ChallengeValidationDetails challenge)
        {
            //setup for temporary DNS Server
            selfDnsServer = new DnsServerAcme(_log);
            var authority = await _dnsClient.GetAuthority(
                challenge.DnsRecordName,
                followCnames: _settings.Validation.AllowDnsSubstitution);
            var record = new DnsValidationRecord(context, authority, challenge.DnsRecordValue);

            await CreateRecord(record);
            selfDnsServer.Listen();

            PreValidate();
        }
        public override async Task<bool> CreateRecord(DnsValidationRecord record)
        {
           selfDnsServer.AddRecord(record.Authority.Domain, record.Value);
            _log.Information("Validation TXT {token} added to DNS Server {answerUri}", record.Value, record.Authority.Domain);
            return true;
        }
        public override async Task DeleteRecord(DnsValidationRecord record)
        {          
        }
        //public override async Task CleanUp()
        //{
        //    selfDnsServer.Dispose();
        //    await base.CleanUp();
        //}
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
