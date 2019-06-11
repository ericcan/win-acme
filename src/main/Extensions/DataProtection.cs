﻿using PKISharp.WACS.Services;
using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace PKISharp.WACS.Extensions
{
    /// <summary>
    /// Adapted from
    /// https://www.thomaslevesque.com/2013/05/21/an-easy-and-secure-way-to-store-a-password-using-data-protection-api/
    /// 
    /// Save string as "enc-[encryptedBase64]" for protected data
    /// Save string as "[base64]" for normal data (e.g. when the setting "EncryptConfig" is disabled
    /// </summary>
    public static class DataProtectionExtensions
    {
        private const string Prefix = "enc-";

        public static string Protect(
            this string clearText,
            string optionalEntropy = null,
            DataProtectionScope scope = DataProtectionScope.LocalMachine)
        {
            if (clearText == null)
                return null;

            byte[] clearBytes = Encoding.UTF8.GetBytes(clearText);
            if (Properties.Settings.Default.EncryptConfig)
            {
                byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                    ? null
                    : Encoding.UTF8.GetBytes(optionalEntropy);
                byte[] encryptedBytes = ProtectedData.Protect(clearBytes, entropyBytes, scope);
                return Prefix + Convert.ToBase64String(encryptedBytes);
            }
            else
            {
                return Convert.ToBase64String(clearBytes);
            }
        }

        public static string Unprotect(
            this string encryptedText,
            string optionalEntropy = null,
            DataProtectionScope scope = DataProtectionScope.LocalMachine)
        {
            if (encryptedText == null)
                return null;
            byte[] clearBytes = null;
            if (encryptedText.StartsWith(Prefix))
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedText.Substring(Prefix.Length));
                byte[] entropyBytes = string.IsNullOrEmpty(optionalEntropy)
                    ? null
                    : Encoding.UTF8.GetBytes(optionalEntropy);
                clearBytes = ProtectedData.Unprotect(encryptedBytes, entropyBytes, scope);
            }
            else
            {
                try
                {
                    clearBytes = Convert.FromBase64String(encryptedText);
                }
                catch
                {
                    return null;
                }
            }
            return Encoding.UTF8.GetString(clearBytes);
        }
    }
    /// <summary>
    /// handles type 'protectedString' for json, including parameter to save as in machine-independent form
    /// </summary>
    public class protectedStringConverter : JsonConverter<string>
    {
        public override void WriteJson(JsonWriter writer, string protectedStr, JsonSerializer serializer)
        {
            try
            {
                string unprotected = protectedStr.Unprotect();
                writer.WriteValue(unprotected.Protect());
            }
            catch
            {
                //couldn't unprotect string; keeping old value
                writer.WriteValue(protectedStr);
            }
        }
        public override string ReadJson(JsonReader reader, Type objectType, string existingValue, bool hasExistingValue, JsonSerializer serializer)
        {
            string s = (string)reader.Value;
            return s;
        }
    }
}
