using System;
using System.IO;
using System.Linq;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.Exceptions;
using WindowsFirewallHelper.FirewallRules;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace WindowsFirewallHelper.Tests
{
    public class FirewallWASTests
    {
        private const string RulesPrefix = "_WFH_TEST_";
        private FirewallWAS _firewall;

        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateDirectApplicationRule()
        {
            var ruleName = RulesPrefix + Guid.NewGuid().ToString("N");
            var fileName = Path.GetTempFileName();
            var rule = _firewall.CreateApplicationRule(
                FirewallProfiles.Domain | FirewallProfiles.Private,
                ruleName,
                FirewallAction.Allow,
                FirewallDirection.Inbound,
                fileName,
                FirewallProtocol.Any
            );

            _firewall.Rules.Add(rule);

            var checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.ApplicationName.ToLower(), fileName.ToLower());
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Domain | FirewallProfiles.Private);

            _firewall.Rules.Remove(rule);

            checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNull(checkRule);
        }

        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateDirectICMPRule()
        {
            var ruleName = RulesPrefix + Guid.NewGuid().ToString("N");
            var rule = new FirewallWASRule(
                ruleName,
                FirewallAction.Allow,
                FirewallDirection.Inbound,
                FirewallProfiles.Domain
            )
            {
                Protocol = FirewallProtocol.ICMPv4,
                RemoteAddresses = new IAddress[] {SingleIP.Parse("192.168.0.1")}
            };

            _firewall.Rules.Add(rule);

            var checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.ICMPv4);
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Domain);

            _firewall.Rules.Remove(rule);

            checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNull(checkRule);
        }

        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateDirectIPv6Rule()
        {
            var ruleName = RulesPrefix + Guid.NewGuid().ToString("N");
            var remoteAddress = SingleIP.Parse("2607:fea8:4260:31a::9");
            var rule = new FirewallWASRule(
                ruleName,
                FirewallAction.Block,
                FirewallDirection.Outbound,
                FirewallProfiles.Public
            )
            {
                Protocol = FirewallProtocol.Any,
                RemoteAddresses = new IAddress[] {remoteAddress}
            };

            _firewall.Rules.Add(rule);

            var checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.IsTrue(checkRule.RemoteAddresses.SequenceEqual(new IAddress[] {remoteAddress}));
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Public);
            ClassicAssert.AreEqual(checkRule.Direction, FirewallDirection.Outbound);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Block);

            _firewall.Rules.Remove(rule);

            checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNull(checkRule);
        }

        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateDirectPortRule()
        {
            var ruleName = RulesPrefix + Guid.NewGuid().ToString("N");
            var portNumber = (ushort) 10011;
            var rule = _firewall.CreatePortRule(
                FirewallProfiles.Domain | FirewallProfiles.Private,
                ruleName,
                FirewallAction.Allow,
                FirewallDirection.Inbound,
                portNumber,
                FirewallProtocol.TCP
            );

            _firewall.Rules.Add(rule);

            var checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.IsTrue(checkRule.LocalPorts.Contains(portNumber));
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Domain | FirewallProfiles.Private);

            _firewall.Rules.Remove(rule);

            checkRule = _firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName);
            ClassicAssert.IsNull(checkRule);
        }


        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateIndirectApplicationRule()
        {
            var firewall = (IFirewall) _firewall;

            var ruleName1 = RulesPrefix + Guid.NewGuid().ToString("N");
            var ruleName2 = RulesPrefix + Guid.NewGuid().ToString("N");
            var ruleName3 = RulesPrefix + Guid.NewGuid().ToString("N");

            var fileName1 = Path.GetTempFileName();
            var fileName2 = Path.GetTempFileName();
            var fileName3 = Path.GetTempFileName();

            var rule1 = firewall.CreateApplicationRule(
                FirewallProfiles.Private,
                ruleName1,
                fileName1
            );
            var rule2 = firewall.CreateApplicationRule(
                FirewallProfiles.Private,
                ruleName2,
                FirewallAction.Allow,
                fileName2
            );
            var rule3 = firewall.CreateApplicationRule(
                FirewallProfiles.Private,
                ruleName3,
                FirewallAction.Allow,
                fileName3,
                FirewallProtocol.Any
            );

            firewall.Rules.Add(rule1);
            firewall.Rules.Add(rule2);
            firewall.Rules.Add(rule3);

            var checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName1);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.ApplicationName.ToLower(), fileName1.ToLower());
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.Any);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName2);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.ApplicationName.ToLower(), fileName2.ToLower());
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.Any);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName3);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.ApplicationName.ToLower(), fileName3.ToLower());
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.Any);

            firewall.Rules.Remove(rule1);
            firewall.Rules.Remove(rule2);
            firewall.Rules.Remove(rule3);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName1);
            ClassicAssert.IsNull(checkRule);
            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName2);
            ClassicAssert.IsNull(checkRule);
            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName3);
            ClassicAssert.IsNull(checkRule);
        }

        [Test]
        public void CreateIndirectBadPortRule()
        {
            var firewall = (IFirewall) _firewall;
            var ruleName = RulesPrefix + Guid.NewGuid().ToString("N");
            ushort portNumber = 10001;

            // Any protocols except TCP and UDP are not supported with Windows Firewall With Advanced Security
            ClassicAssert.Throws<FirewallWASInvalidProtocolException>(() =>
                {
                    firewall.CreatePortRule(
                        FirewallProfiles.Private,
                        ruleName,
                        FirewallAction.Allow,
                        portNumber,
                        FirewallProtocol.Any
                    );
                }
            );
        }

        [Test]
        // ReSharper disable once TooManyDeclarations
        public void CreateIndirectPortRule()
        {
            var firewall = (IFirewall) _firewall;

            var ruleName1 = RulesPrefix + Guid.NewGuid().ToString("N");
            var ruleName2 = RulesPrefix + Guid.NewGuid().ToString("N");
            var ruleName3 = RulesPrefix + Guid.NewGuid().ToString("N");
            var ruleName4 = RulesPrefix + Guid.NewGuid().ToString("N");

            ushort portNumber1 = 10001;
            ushort portNumber2 = 10002;
            ushort portNumber3 = 10003;
            ushort portNumber4 = 10004;

            var rule1 = firewall.CreatePortRule(
                FirewallProfiles.Private,
                ruleName1,
                portNumber1
            );
            var rule2 = firewall.CreatePortRule(
                FirewallProfiles.Private,
                ruleName2,
                FirewallAction.Allow,
                portNumber2
            );
            var rule3 = firewall.CreatePortRule(
                FirewallProfiles.Private,
                ruleName3,
                FirewallAction.Allow,
                portNumber3,
                FirewallProtocol.TCP
            );
            var rule4 = firewall.CreatePortRule(
                FirewallProfiles.Domain,
                ruleName4,
                FirewallAction.Allow,
                portNumber4,
                FirewallProtocol.UDP
            );

            firewall.Rules.Add(rule1);
            firewall.Rules.Add(rule2);
            firewall.Rules.Add(rule3);
            firewall.Rules.Add(rule4);

            var checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName1);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.LocalPorts, new[] {portNumber1});
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.TCP);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName2);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.LocalPorts, new[] {portNumber2});
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.TCP);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName3);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.LocalPorts, new[] {portNumber3});
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Private);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.TCP);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName4);
            ClassicAssert.IsNotNull(checkRule);
            ClassicAssert.AreEqual(checkRule.LocalPorts, new[] {portNumber4});
            ClassicAssert.AreEqual(checkRule.Profiles, FirewallProfiles.Domain);
            ClassicAssert.AreEqual(checkRule.Action, FirewallAction.Allow);
            ClassicAssert.AreEqual(checkRule.Protocol, FirewallProtocol.UDP);

            firewall.Rules.Remove(rule1);
            firewall.Rules.Remove(rule2);
            firewall.Rules.Remove(rule3);
            firewall.Rules.Remove(rule4);

            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName1);
            ClassicAssert.IsNull(checkRule);
            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName2);
            ClassicAssert.IsNull(checkRule);
            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName3);
            ClassicAssert.IsNull(checkRule);
            checkRule = firewall.Rules.FirstOrDefault(firewallRule => firewallRule.Name == ruleName4);
            ClassicAssert.IsNull(checkRule);
        }

        [SetUp]
        public void Setup()
        {
            _firewall = FirewallWAS.Instance;
        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                var rulesToBeDeleted = _firewall.Rules.Where(rule => rule.Name.StartsWith(RulesPrefix)).ToArray();

                foreach (var firewallRule in rulesToBeDeleted)
                {
                    _firewall.Rules.Remove(firewallRule);
                }
            }
            catch (Exception)
            {
                // ignored
            }

            _firewall = null;
        }
    }
}