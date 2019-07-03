import unittest
from mock import MagicMock, patch

from se_dns import dnsutil


class TestCache(unittest.TestCase):
    """Tests for the dnsutil.Cache class."""

    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_resolver = MagicMock()
        self.mock_cache = MagicMock()
        patch("se_dns.dnsutil.logging.getLogger",
              return_value=self.mock_logger).start()
        patch("se_dns.dnsutil.dns.resolver.Resolver",
              return_value=self.mock_resolver).start()
        patch("se_dns.dnsutil.dns.resolver.Cache",
              return_value=self.mock_cache).start()
        self.mock_rdtype = patch("se_dns.dnsutil.dns.rdatatype.from_text").start()
        self.mock_rdclass = patch("se_dns.dnsutil.dns.rdataclass.from_text").start()

    def tearDown(self):
        patch.stopall()

    def test_init(self):
        """Test that we initialize the fields correctly."""
        tested_obj = dnsutil.Cache("dnsserver")

        self.assertEqual(tested_obj.queryObj.nameservers, ["dnsserver"])
        self.assertEqual(tested_obj.queryObj.lifetime, 10)
        self.mock_logger.warn.assert_not_called()

    def test_lookup_use_cache(self):
        """Test that the lookup uses the cache values."""
        reply = MagicMock()
        items = [MagicMock(to_text=lambda: 1)]
        reply.response.answer = [
            MagicMock(to_rdataset=lambda: MagicMock(items=items))
        ]
        self.mock_cache.get.return_value = reply

        tested_obj = dnsutil.Cache("dnsserver")
        result = tested_obj.lookup("test.question")

        self.assertEqual(result, [1])
        tested_obj.queryObj.query.assert_not_called()

    def test_lookup_no_cache(self):
        """Test that we query correctly and update the cache when no cache
        is available."""
        self.mock_cache.get.return_value = None
        cache_line = (
            "test.question",
            self.mock_rdtype.return_value,
            self.mock_rdclass.return_value
        )
        tested_obj = dnsutil.Cache("dnsserver")
        tested_obj.lookup("test.question")

        query_func = tested_obj.queryObj.query
        query_func.assert_called_with(*cache_line)
        tested_obj.queryObj.cache.put.assert_called_with(cache_line,
                                                         query_func.return_value)

    def test_lookup_cache_failure(self):
        """Test that we use the failure cache with various errors."""
        question = "test.question"
        side_effects = [
            dnsutil.dns.resolver.NXDOMAIN,
            dnsutil.dns.exception.Timeout,
            dnsutil.dns.resolver.NoAnswer,
            IndexError,
            dnsutil.struct.error
        ]

        for side_effect in side_effects:
            tested_obj = dnsutil.Cache('dnsserver')
            tested_obj.queryObj.cache.get = MagicMock(return_value=None)
            tested_obj.queryObj.query.side_effect = [side_effect, MagicMock()]

            # first time should fail
            result = tested_obj.lookup(question)
            self.assertEqual(result, [])

            # second time we should use the failures cache
            result = tested_obj.lookup(question)
            self.assertEqual(result, [])
            tested_obj.queryObj.cache.get.assert_called_once()


class Test_DNSCache(unittest.TestCase):
    """Tests for the dnsutil._DNSCache class."""

    def setUp(self):
        self.mock_resolver = MagicMock()
        self.mock_cache = MagicMock()
        patch("se_dns.dnsutil.logging.getLogger").start()
        patch("se_dns.dnsutil.dns.resolver.Resolver",
              return_value=self.mock_resolver).start()
        patch("se_dns.dnsutil.dns.resolver.Cache",
              return_value=self.mock_cache).start()
        patch("se_dns.dnsutil.os.path.exists", return_value=False).start()
        self.mock_lookup = patch("se_dns.dnsutil.Cache.lookup",
                                 return_value=["cache.result"]).start()

    def tearDown(self):
        patch.stopall()

    def test_init(self):
        """Test that we initialize fields correctly."""
        tested_obj = dnsutil._DNSCache()
        self.assertEqual(tested_obj.COMBINED, "")
        self.assertEqual(tested_obj.COMBINED_DNSBL, {})
        self.assertEqual(tested_obj.queryObj.lifetime, 10)

    def test_lookup(self):
        """Test that we return the super lookup method result if
        the question is not listed in the combined URLBL or DNSBL lists."""
        question = "list1.dnsbl.example.com"
        tested_obj = dnsutil._DNSCache()
        result = tested_obj.lookup(question)
        self.assertEqual(result, ["cache.result"])

    def test_lookup_combined_no_match(self):
        """Test that we rewrite the query if it's handled by the combined DNSBL
        list, but the question is not listed."""
        question = "test.list1.dnsbl.example.com"
        tested_obj = dnsutil._DNSCache()
        tested_obj.COMBINED = "combined.list"
        tested_obj.COMBINED_DNSBL_REVERSE = {"cache1.result": "list1.dnsbl.example.com"}
        tested_obj.COMBINED_DNSBL_REVERSE_VALUES = tested_obj.COMBINED_DNSBL_REVERSE.values()

        result = tested_obj.lookup(question)
        self.assertEqual(result, [])
        self.mock_lookup.assert_called_with('test.combined.list', 'A', 'IN', False)

    def test_lookup_combined_match(self):
        """Test that we rewrite the query if it's handled by the combined DNSBL
        list and the question is listed."""
        question = "test.list1.dnsbl.example.com"
        tested_obj = dnsutil._DNSCache()
        tested_obj.COMBINED = "combined.list"
        tested_obj.COMBINED_DNSBL_REVERSE = {"cache.result": "list1.dnsbl.example.com"}
        tested_obj.COMBINED_DNSBL_REVERSE_VALUES = tested_obj.COMBINED_DNSBL_REVERSE.values()

        result = tested_obj.lookup(question)
        self.assertEqual(result, ["127.0.0.2"])
        self.mock_lookup.assert_called_with('test.combined.list', 'A', 'IN', False)

    def test_lookup_combined_url_no_match(self):
        """Test that we rewrite the query if it's handled by the combined URLBL
        list, but the question is not listed."""
        question = "test.list1.urlbl.example.com"
        tested_obj = dnsutil._DNSCache()
        tested_obj.COMBINED_URL = "combined.url"
        tested_obj.COMBINED_URLBL_REVERSE = {"cache1.result": "list1.urlbl.example.com"}
        tested_obj.COMBINED_URLBL_REVERSE_VALUES = tested_obj.COMBINED_URLBL_REVERSE.values()

        result = tested_obj.lookup(question)
        self.assertEqual(result, [])
        self.mock_lookup.assert_called_with('test.combined.url', 'A', 'IN', False)

    def test_lookup_combined_url_match(self):
        """Test that we rewrite the query if it's handled by the combined URLBL
        list and the question is listed."""
        question = "test.list1.urlbl.example.com"
        tested_obj = dnsutil._DNSCache()
        tested_obj.COMBINED_URL = "combined.url"
        tested_obj.COMBINED_URLBL_REVERSE = {"cache.result": "list1.urlbl.example.com"}
        tested_obj.COMBINED_URLBL_REVERSE_VALUES = tested_obj.COMBINED_URLBL_REVERSE.values()

        result = tested_obj.lookup(question)
        self.assertEqual(result, ["127.0.0.2"])
        self.mock_lookup.assert_called_with('test.combined.url', 'A', 'IN', False)


class TestDNSCache(unittest.TestCase):
    """Tests for the dnsutil.DNSCache class."""

    def setUp(self):
        self.mock_global_cache = patch("se_dns.dnsutil._DNS_CACHE").start()

    def tearDown(self):
        patch.stopall()

    def test_lookup_uses_global_cache(self):
        """Test that we use the global cache when doing a lookup."""
        question = "question.test"
        tested_obj = dnsutil.DNSCache(20)
        tested_obj.lookup(question)

        self.mock_global_cache.lookup.assert_called_with(question, "A", "IN", False)
        self.assertEqual(self.mock_global_cache.queryObj.lifetime, 20)


def suite():
    """Create a suite that includes all tests."""
    test_suite = unittest.TestSuite()
    test_suite.addTest(unittest.makeSuite(TestCache, 'test'))
    test_suite.addTest(unittest.makeSuite(Test_DNSCache, 'test'))
    test_suite.addTest(unittest.makeSuite(TestDNSCache, 'test'))

    return test_suite


if __name__ == '__main__':
    unittest.main()
