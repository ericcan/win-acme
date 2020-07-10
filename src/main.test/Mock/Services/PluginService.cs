﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using PKISharp.WACS.Services;

namespace PKISharp.WACS.UnitTests.Mock.Services
{
    class MockPluginService : PluginService
    {
        public MockPluginService(ILogService logger) : base(logger) { }

        internal override List<Type> GetTypes()
        {
            var ret = new List<Type>();
            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                if ((assembly.FullName ?? "").Contains("wacs") && !(assembly.FullName ?? "").Contains("test"))
                {
                    IEnumerable<Type> types = new List<Type>();
                    try
                    {
                        types = GetTypesFromAssembly(assembly).ToList();
                    }
                    catch (ReflectionTypeLoadException rex)
                    {
                        types = rex.Types ?? new Type[] { };
                    }
                    catch (Exception)
                    {
                    }
                    ret.AddRange(types);
                }
            }
            return ret;
        }

    }
}
