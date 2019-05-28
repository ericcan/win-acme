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
        private IInputService _input;
        private MasterFile masterFile;
        private DnsServer server;
        public SelfDNS(
            LookupClientProvider dnsClient,
            ILogService log,
            IInputService input,
            SelfDNSOptions options, string
            identifier) :
            base(dnsClient, log, options, identifier)
        {
            // Usually it's a big no-no to rely on user input in validation plugin
            // because this should be able to run unattended. This plugin is for testing
            // only and therefor we will allow it. Future versions might be more advanced,
            // e.g. shoot an email to an admin and complete the order later.
            _input = input;
            masterFile = new MasterFile();
            server = new DnsServer(masterFile, "8.8.8.8");
            server.Responded += (sender, e) => { _input.Show("REQ:", e.Request.ToString()); _input.Show("RES:", e.Response.ToString()); };
            server.Listening += (sender, e) => _input.Show("Listening for DNS requests");
            server.Errored += (sender, e) =>
            {
                _input.Show("Errored: ${e.Exception}");
                ResponseException responseError = e.Exception as ResponseException;
                if (responseError != null) _input.Show(responseError.Response.ToString());
            };
        }


        public override void CreateRecord(string recordName, string token)
        {
            masterFile.AddTextResourceRecord(recordName, "", token);
            masterFile.AddNameServerResourceRecord(recordName, "8.8.8.8");
        }
        public override void PrepareChallenge()
        {
            CreateRecord(_challenge.DnsRecordName, _challenge.DnsRecordValue);
            server.Listen();

            _log.Information("Answer should now be available at {answerUri}", _challenge.DnsRecordName);

            // Verify that the record was created succesfully and wait for possible
            // propagation/caching/TTL issues to resolve themselves naturally
            if (!PreValidate())
            {
                _log.Information("It looks like validation is going to fail, but we will try now anyway...");

            }

        }
        public override void DeleteRecord(string recordName, string token)
        {
            server.Dispose();
        }
        protected new bool PreValidate()
        {
            try
            {
                var domainName = _challenge.DnsRecordName;
                LookupClientWrapper dnsClient;
                dnsClient = _dnsClientProvider.GetClient(domainName);

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
