using System;
using WindowsFirewallHelper.Addresses;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace WindowsFirewallHelper.Tests
{
    public class SpecialAddressTests
    {
        [Test]
        public void DefaultGatewayValidParse()
        {
            // ReSharper disable once StringLiteralTypo
            var str = "Defaultgateway";
            var address = SpecialAddress.Parse(str);

            ClassicAssert.AreEqual(new DefaultGateway(), address);
            ClassicAssert.AreEqual(str, address.ToString());
        }

        [Test]
        public void DHCPServiceValidParse()
        {
            var str = "DHCP";
            var address = SpecialAddress.Parse(str);

            ClassicAssert.AreEqual(new DHCPService(), address);
            ClassicAssert.AreEqual(str, address.ToString());
        }

        [Test]
        public void DNSServiceValidParse()
        {
            var str = "DNS";
            var address = SpecialAddress.Parse(str);

            ClassicAssert.AreEqual(new DNSService(), address);
            ClassicAssert.AreEqual(str, address.ToString());
        }

        [Test]
        public void LocalSubnetValidParse()
        {
            var str = "LocalSubnet";
            var address = SpecialAddress.Parse(str);

            ClassicAssert.AreEqual(new LocalSubnet(), address);
            ClassicAssert.AreEqual(str, address.ToString());
        }

        [Test]
        public void SpecialAddressInvalidParses()
        {
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("");
                }
            );
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("SOME_UNKNOWN_STRING");
                }
            );
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("*");
                }
            );

            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("192.168.1.0");
                }
            );
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("2001:1::");
                }
            );

            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("192.168.2.0/24");
                }
            );
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("2001:1::/112");
                }
            );

            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("192.168.3.0-192.168.4.0");
                }
            );
            ClassicAssert.Throws<FormatException>(() =>
                {
                    SpecialAddress.Parse("2001:2::-2001:3::");
                }
            );
        }

        [Test]
        public void WINSServiceValidParse()
        {
            var str = "WINS";
            var address = SpecialAddress.Parse(str);

            ClassicAssert.AreEqual(new WINSService(), address);
            ClassicAssert.AreEqual(str, address.ToString());
        }
    }
}