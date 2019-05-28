using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Services;
using System.Linq;
using System.Threading.Tasks;
using DNS.Server;
using DNS.Client;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    class Manual : DnsValidation<ManualOptions, Manual>
    {
        private IInputService _input;
        private MasterFile masterFile;
        private DnsServer server;
        public Manual(
            LookupClientProvider dnsClient,  
            ILogService log, 
            IInputService input, 
            ManualOptions options, string 
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
            server.Responded += (sender, e) => { _input.Show("{e.Request} => {e.Response}"); };
            server.Listening += (sender, e) => _input.Show("Listening for DNS requests");
            server.Errored += (sender, e) => {
                _input.Show("Errored: {e.Exception}");
                ResponseException responseError = e.Exception as ResponseException;
                if (responseError != null) _input.Show(responseError.Response.ToString());
                masterFile.AddTextResourceRecord("_acme-challenge.candell.org.", "", "hiTokenTest");
            };
            server.Listen();
        }


    public override void CreateRecord(string recordName, string token)
        {

            masterFile.AddTextResourceRecord(recordName, "", token);
            _input.Show("Create an NS record for {recordname} pointing to this server");
            _input.Wait("Please press enter after you've created and verified the record");

            //_input.Show("Domain", _identifier, true);
            //_input.Show("Record", recordName);
            //_input.Show("Type", "TXT");
            //_input.Show("Content", $"\"{token}\"");
            //_input.Show("Note 1", "Some DNS control panels add quotes automatically. Only one set is required.");
            //_input.Show("Note 2", "Make sure your name servers are synchronised, this may take several minutes!");
            //_input.Wait("Please press enter after you've created and verified the record");

            // Pre-pre-validate, allowing the manual user to correct mistakes
            while (true)
            {
                if (PreValidate())
                {
                    break;
                }
                else
                {
                    var retry = _input.PromptYesNo(
                        "The correct record is not yet found by the local resolver. " +
                        "Check your configuration and/or wait for the name servers to " +
                        "synchronize and press <Enter> to try again. Answer 'N' to " +
                        "try ACME validation anyway.", true);
                    if (!retry)
                    {
                        break;
                    }
                }
            }
        }

        public override void DeleteRecord(string recordName, string token)
        {
            server.Dispose();
            _input.Show("Domain", _identifier, true);
            _input.Show("Record", recordName);
            _input.Show("Type", "TXT");
            _input.Show("Content", $"\"{token}\"");
            _input.Wait("Please press enter after you've deleted the record");
        }
    }
}
