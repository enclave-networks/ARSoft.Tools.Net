using ARSoft.Tools.Net;
using ARSoft.Tools.Net.Dns;
using NUnit.Framework;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Enclave.ARSoft.Tools.Net.Tests
{
    public class Tests
    {
        [Test]
        public async Task ManualTest()
        {
            var testClient = new DnsClient(IPAddress.Parse("100.84.16.18"), 10);

            using var cancelSource = new CancellationTokenSource();

            var token = cancelSource.Token;

            cancelSource.CancelAfter(4000);

            var result = await testClient.ResolveAsync(DomainName.Parse("4yw3dw.id.enclave"));

            Assert.True(result.AnswerRecords.Any(x => x is ARecord arec && arec.Address.Equals(IPAddress.Parse("100.119.20.243"))));
        }
    }
}