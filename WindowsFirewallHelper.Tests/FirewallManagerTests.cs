using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace WindowsFirewallHelper.Tests
{
    public class FirewallManagerTests
    {
        [Test]
        public void TryGetInstanceTest()
        {
            // NOTE: this may vary depending on the machine on which it is run.
            var successful = FirewallManager.TryGetInstance(out var instance);

            if (successful)
            {
                ClassicAssert.IsNotNull(instance);
            }
            else
            {
                ClassicAssert.IsNull(instance);
            }
        }

        [Test]
        public void TryGetRegisteredProductsTest()
        {
            // NOTE: this may vary depending on the machine on which it is run.
            var successful = FirewallManager.TryGetRegisteredProducts(out var collection);

            if (successful)
            {
                ClassicAssert.IsNotNull(collection);
            }
            else
            {
                ClassicAssert.IsNull(collection);
            }
        }
    }
}
