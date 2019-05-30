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
        private MasterFile DNSRecords;
        private DnsServer server;
        public SelfDNS(
            LookupClientProvider dnsClient,
            ILogService log,
            SelfDNSOptions options, string
            identifier) :
            base(dnsClient, log, options, identifier)
        {
            DNSRecords = new MasterFile();
            server = new DnsServer(DNSRecords, "8.8.8.8");
            server.Responded += (sender, e) => 
            {
                _log.Information("DNS Server received lookup request from {remote}", e.Remote.Address.ToString() );
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
              //  _log.Debug("DNS Response: " + e.Response.ToString());
            };
            server.Listening += (sender, e) => _log.Information("DNS Server listening...");
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
            _log.Information("Validation TXT {token} added to DNS Server {answerUri}", _challenge.DnsRecordValue, _challenge.DnsRecordName);
            server.Listen();

            PreValidate(false);
        }
        public override void CreateRecord(string recordName, string token)
        {
            DNSRecords.AddTextResourceRecord(recordName, "", token);
            DNSRecords.AddNameServerResourceRecord(recordName, "aws.candell.org"); //need to replace with user parameter
        }
        public override void DeleteRecord(string recordName, string token)
        {
            server.Dispose();
        }

    }
}
