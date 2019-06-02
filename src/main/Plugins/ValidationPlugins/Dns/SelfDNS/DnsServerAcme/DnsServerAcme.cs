﻿using System;
using DNS.Client;
using PKISharp.WACS.Services;


namespace DNS.Server.Acme {
    class DnsServerAcme : IDisposable
    {
        private MasterFile DNSRecords;
        private DnsServer selfDnsServer;
        private ILogService _log;
        public bool reqReceived = false;
        public DnsServerAcme(ILogService log)
        {
            _log = log;
            //initialization here
            DNSRecords = new MasterFile();
            selfDnsServer = new DnsServer(DNSRecords, "8.8.8.8");
            selfDnsServer.Responded += (sender, e) =>
            {
                reqReceived = true;
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
            selfDnsServer.Listening += (sender, e) => _log.Information("DNS Server listening...");
            selfDnsServer.Errored += (sender, e) =>
            {
                _log.Debug("Errored: {Error}", e.Exception);
                ResponseException responseError = e.Exception as ResponseException;
                if (responseError != null) _log.Debug(responseError.Response.ToString());
            };
        }
        public void AddRecord(string recordName, string token)
        {
            DNSRecords.AddTextResourceRecord(recordName, "", token);
        }
        public async void Listen()
        {
            await selfDnsServer.Listen();
        }

        public void Dispose()
        {
            selfDnsServer.Dispose();
        }
    }
}
