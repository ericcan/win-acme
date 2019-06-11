﻿using Autofac;
using PKISharp.WACS.Acme;
using PKISharp.WACS.Clients.IIS;
using PKISharp.WACS.DomainObjects;
using PKISharp.WACS.Extensions;
using PKISharp.WACS.Services;
using PKISharp.WACS.Services.Legacy;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;

namespace PKISharp.WACS
{
    internal partial class Wacs
    {
        /// <summary>
        /// Main user experience
        /// </summary>
        private void MainMenu()
        {
            var options = new List<Choice<Action>>
            {
                Choice.Create<Action>(() => SetupRenewal(RunLevel.Interactive | RunLevel.Simple), "Create new certificate", "N", true),
                Choice.Create<Action>(() => SetupRenewal(RunLevel.Interactive | RunLevel.Advanced), "Create new certificate with advanced options", "M"),
                Choice.Create<Action>(() => ShowRenewals(), "List scheduled renewals", "L"),
                Choice.Create<Action>(() => CheckRenewals(RunLevel.Interactive), "Renew scheduled", "R"),
                Choice.Create<Action>(() => RenewSpecific(), "Renew specific", "S"),
                Choice.Create<Action>(() => CheckRenewals(RunLevel.Interactive | RunLevel.ForceRenew), "Renew *all*", "A"),
                Choice.Create<Action>(() => ExtraMenu(), "More options...", "O"),
                Choice.Create<Action>(() => { _args.CloseOnFinish = true; _args.Test = false; }, "Quit", "Q")
            };
            // Simple mode not available without IIS installed and configured, because it defaults to the IIS installer
            if (!_container.Resolve<IIISClient>().HasWebSites)
            {
                options.RemoveAt(0);
            }
            _input.ChooseFromList("Please choose from the menu", options).Invoke();
        }

        /// <summary>
        /// Less common options
        /// </summary>
        private void ExtraMenu()
        {
            var options = new List<Choice<Action>>
            {
                Choice.Create<Action>(() => CancelRenewal(RunLevel.Interactive), "Cancel scheduled renewal", "C"),
                Choice.Create<Action>(() => CancelAllRenewals(), "Cancel *all* scheduled renewals", "X"),
                Choice.Create<Action>(() => RevokeCertificate(), "Revoke certificate", "V"),
                Choice.Create<Action>(() => CreateScheduledTask(), "(Re)create scheduled task", "T"),
                Choice.Create<Action>(() => TestEmail(), "Test email notification", "E"),
                Choice.Create<Action>(() => UpdateAccount(RunLevel.Interactive), "ACME account details", "A"),
                Choice.Create<Action>(() => Import(RunLevel.Interactive), "Import scheduled renewals from WACS/LEWS 1.9.x", "I"),
                Choice.Create<Action>(() => Migrate(RunLevel.Interactive), "Export/Import data to migrate to new machine", "M"),
                Choice.Create<Action>(() => { }, "Back", "Q", true)
            };
            _input.ChooseFromList("Please choose from the menu", options).Invoke();
        }

        /// <summary>
        /// Show certificate details
        /// </summary>
        private void ShowRenewals()
        {
            var renewal = _input.ChooseFromList("Show details for renewal?",
                _renewalService.Renewals,
                x => Choice.Create(x, color: x.History.Last().Success ? 
                                                x.Date < DateTime.Now ? 
                                                    ConsoleColor.DarkYellow : 
                                                    ConsoleColor.Green : 
                                                ConsoleColor.Red),
                "Back");

            if (renewal != null)
            {
                try
                {
                    _input.Show("Renewal");
                    _input.Show("Id", renewal.Id);
                    _input.Show("File", $"{renewal.Id}.renewal.json");
                    _input.Show("FriendlyName", string.IsNullOrEmpty(renewal.FriendlyName) ? $"[Auto] {renewal.LastFriendlyName}" : renewal.FriendlyName);
                    string pfxPW = null;
                    try
                    { 
                        pfxPW = renewal.PfxPassword;
                    }
                    catch
                    {
                        pfxPW = "Couldn't unprotect PFX password";
                        _log.Error("Password unprotecting failed, likely due to encryption on a different machine.");
                    }
                    _input.Show(".pfx password", pfxPW);
                    _input.Show("Renewal due", renewal.Date.ToUserString());
                    _input.Show("Renewed", $"{renewal.History.Count} times");
                    renewal.TargetPluginOptions.Show(_input);
                    renewal.ValidationPluginOptions.Show(_input);
                    renewal.CsrPluginOptions.Show(_input);
                    foreach (var ipo in renewal.StorePluginOptions)
                    {
                        ipo.Show(_input);
                    }
                    foreach (var ipo in renewal.InstallationPluginOptions)
                    {
                        ipo.Show(_input);
                    }
                    _input.Show("History");
                    _input.WritePagedList(renewal.History.Select(x => Choice.Create(x)));
                }
                catch (Exception ex)
                {
                    _log.Error(ex, "Unable to list details for target");
                }
            }
        }

        /// <summary>
        /// Renew specific certificate
        /// </summary>
        private void RenewSpecific()
        {
            var renewal = _input.ChooseFromList("Which renewal would you like to run?",
                _renewalService.Renewals,
                x => Choice.Create(x),
                "Back");
            if (renewal != null)
            {
                var runLevel = RunLevel.Interactive | RunLevel.ForceRenew;
                if (_args.Force)
                {
                    runLevel |= RunLevel.IgnoreCache;
                }
                WarnAboutRenewalArguments();
                ProcessRenewal(renewal, runLevel);
            }
        }

        /// <summary>
        /// Revoke certificate
        /// </summary>
        private void RevokeCertificate()
        {
            var renewal = _input.ChooseFromList("Which certificate would you like to revoke?",
                _renewalService.Renewals,
                x => Choice.Create(x),
                "Back");
            if (renewal != null)
            {
                if (_input.PromptYesNo($"Are you sure you want to revoke {renewal}? This should only be done in case of a security breach.", false))
                {
                    using (var scope = _scopeBuilder.Execution(_container, renewal, RunLevel.Unattended))
                    {
                        var cs = scope.Resolve<ICertificateService>();
                        try
                        {
                            cs.RevokeCertificate(renewal);
                            renewal.History.Add(new RenewResult("Certificate revoked"));
                        }
                        catch (Exception ex)
                        {
                            HandleException(ex);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Cancel all renewals
        /// </summary>
        private void CancelAllRenewals()
        {
            var renewals = _renewalService.Renewals;
            _input.WritePagedList(renewals.Select(x => Choice.Create(x)));
            if (_input.PromptYesNo("Are you sure you want to cancel all of these?", false))
            {
                _renewalService.Clear();
            }
        }

        /// <summary>
        /// Recreate the scheduled task
        /// </summary>
        private void CreateScheduledTask()
        {
            var taskScheduler = _container.Resolve<TaskSchedulerService>();
            taskScheduler.EnsureTaskScheduler(RunLevel.Interactive | RunLevel.Advanced);
        }

        /// <summary>
        /// Test notification email
        /// </summary>
        private void TestEmail()
        {
            if (!_email.Enabled)
            {
                _log.Error("Email notifications not enabled. Input an SMTP server, sender and receiver in settings.config to enable this.");
            }
            else
            {
                _log.Information("Sending test message...");
                _email.Send("Test notification", 
                    "<p>If you are reading this, it means you will receive notifications about critical errors in the future.</p>",
                    MailPriority.Normal);
                _log.Information("Test message sent!");
            }
        }

        /// <summary>
        /// Load renewals from 1.9.x
        /// </summary>
        private void Import(RunLevel runLevel)
        {
            var importUri = _args.GetBaseUri(true);
            if (runLevel.HasFlag(RunLevel.Interactive))
            {
                var alt = _input.RequestString($"Importing renewals for {importUri}, enter to accept or type an alternative");
                if (!string.IsNullOrEmpty(alt))
                {
                    importUri = alt;
                }
            }
            using (var scope = _scopeBuilder.Legacy(_container, importUri, _args.GetBaseUri()))
            {
                var importer = scope.Resolve<Importer>();
                importer.Import();
            }
        }
        /// <summary>
        /// Export all machine-dependent information for Migration to new machine
        /// </summary>
        private void Migrate(RunLevel runLevel)
        {
            _log.Information("To move your installation of win-acme to another machine, you will want " +
            "to copy the data directory's files to the new machine. However, if you use the Encrypted Configuration option, your renewal " +
            "files contain protected data that is dependent on your local machine. You can " +
            "use this tools to temporarily unprotect your data before moving from the old machine. " +
            "The renewal files includes passwords for your certificates, other passwords/keys, and a key used " +
            "for signing requests for new certificates.");
            _log.Information("To remove machine-dependent protections, use the following steps. ");
            _log.Information("  1. On your old machine, set the EncryptConfig setting to false");
            _log.Information("  2. Run this option; all protected values will be unprotected.");
            _log.Information("  3. Copy your data files to the new machine.");
            _log.Information("  4. On the new machine, set the EncryptConfig setting to true");
            _log.Information("  5. Run this option; all unprotected values will be saved with protection");

           var settings = _container.Resolve<ISettingsService>();
            _log.Information("Data directory: {settings}", settings.ConfigPath);
            bool encryptConfig = Properties.Settings.Default.EncryptConfig;
            _log.Information("Current EncryptConfig setting: {EncryptConfig}", encryptConfig);
            bool response = false;
            response = _input.PromptYesNo($"Save all renewal files {(encryptConfig?"with":"without")} encryption?", false);
            if (response==true)
            {
                _renewalService.Export(); //re-saves all renewals, forcing re-write of all protected strings decorated with [jsonConverter(typeOf(protectedStringConverter())]

                var acmeClient = _container.Resolve<AcmeClient>();
                acmeClient.ExportSigner(); //re-writes the signer file
                _log.Information("Your files are re-saved with encryption turned {onoff}",encryptConfig? "on":"off");
            }
        }
        /// <summary>
        /// Check/update account information
        /// </summary>
        /// <param name="runLevel"></param>
        private void UpdateAccount(RunLevel runLevel)
        {
            var acmeClient = _container.Resolve<AcmeClient>();
            _input.Show("Account ID", acmeClient.Account.Payload.Id, true);
            _input.Show("Created", acmeClient.Account.Payload.CreatedAt);
            _input.Show("Initial IP", acmeClient.Account.Payload.InitialIp);
            _input.Show("Status", acmeClient.Account.Payload.Status);
            if (acmeClient.Account.Payload.Contact != null && 
                acmeClient.Account.Payload.Contact.Length > 0)
            {
                _input.Show("Contact(s)", string.Join(", ", acmeClient.Account.Payload.Contact));
            }
            else
            {
                _input.Show("Contact(s)", "(none)");
            }
            if (_input.PromptYesNo("Modify contacts?", false))
            {
                acmeClient.ChangeContacts();
                UpdateAccount(runLevel);
            }
        }
    }
}
