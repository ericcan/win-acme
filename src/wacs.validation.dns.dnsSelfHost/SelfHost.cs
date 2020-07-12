﻿using ACMESharp.Authorizations;
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
            SelfDNSOptions options) :
            base(dnsClient, log, settings)
        {
        }
        public override async Task PrepareChallenge(ValidationContext context, Dns01ChallengeValidationDetails challenge)
        {
            //setup for temporary DNS Server
            selfDnsServer = new DnsServerAcme(_log);
            _log.Information("Get Authority called");
            var authority = await _dnsClient.GetAuthority(
                challenge.DnsRecordName,
                followCnames: false);
            var record = new DnsValidationRecord(context, authority, challenge.DnsRecordValue);
            await CreateRecord(record);
            selfDnsServer.Listen();

            await PreValidate(record);
        }
        public override async Task<bool> CreateRecord(DnsValidationRecord record)
        {
           selfDnsServer.AddRecord(record.Authority.Domain, record.Value);
            _log.Information("Validation TXT {token} added to DNS Server {answerUri}", record.Value, record.Authority.Domain);
            return true;
        }
        public override async Task DeleteRecord(DnsValidationRecord record)
        {
            selfDnsServer.Dispose();
        }
        //public override async Task CleanUp()
        //{
        //    selfDnsServer.Dispose();
        //    await base.CleanUp();
        //}
        protected async Task<bool> PreValidate(DnsValidationRecord record)
        {
            try
            {
                LookupClientWrapper dnsClient;

                dnsClient = _dnsClient.GetDefaultClient(0);

                var tokens = await dnsClient.GetTxtRecords(record.Authority.Domain);
                if (tokens.Contains(record.Value))
                {
                    _log.Information("Preliminary validation succeeded: {ExpectedTxtRecord} found in {TxtRecords}", record.Value, String.Join(", ", tokens));
                    return true;
                }
                else if (!tokens.Any())
                {
                    _log.Warning("Preliminary validation failed: no TXT records found");
                }
                else
                {
                    _log.Warning("Preliminary validation failed: {ExpectedTxtRecord} not found in {TxtRecords}", record.Value, String.Join(", ", tokens));
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
