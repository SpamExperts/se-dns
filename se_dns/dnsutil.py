"""A wrapper around dnspython.

The wrapper adds two sets of functionality.

Firstly, it provides a single cache object, whenever possible, that is
used throughout the lifetime of the process.  This maximises the use of
the cached information, without having to pass a cache object around to
different parts of the code.  The code handles the case where the
timeout for the cache is different, without the caller needing to
manage that.

Secondly, it includes a transparent shortcut for various DNSBL lookups
where we have a mirror of the list, and the list provides only a
"yes listed" or "no not listed" response (or if it provides more
responses, we are not interested in them).  It does this by looking up
the value in a "combined" result, which provides results for many
different lists, for the first lookup, and then uses that information
for all subsequent checks.  From the caller's point of view, the
original list is being checked.

This code was originally based on the dnscache in SpamBayes.
"""

from __future__ import absolute_import

import os
import json
import struct
import random
import logging

import dns.resolver
import dns.exception
import dns.rdatatype
import dns.rdataclass
import dns.reversename


DNSException = dns.exception.DNSException
EmptyLabel = dns.name.EmptyLabel
LabelTooLong = dns.name.LabelTooLong

# Default config_path hardcoded
CONFIG_PATH = "/etc/combined_lists.json"


class Cache(object):
    """Provide a simple-to-use interface to DNS lookups, which caches the
    results in memory."""
    timeout_log_level = "info"

    def __init__(self, dnsserver=None, dnstimeout=10,
                 minttl=0, cachefile=""):
        self.logger = logging.getLogger("se-dns")
        # We don't use the cachefile argument, but it may be provided.
        # XXX We can probably just drop cachefile now.
        if cachefile:
            self.logger.warn("Caching to file is not supported.")

        # Some servers always return a TTL of zero. In those cases, turning
        # this up a bit is probably reasonable.
        self.minTTL = minttl

        self.queryObj = dns.resolver.Resolver()
        if dnsserver:
            self.queryObj.nameservers = [dnsserver]

        # How long to wait for the server (in seconds).
        # dnspython has a "timeout" value (for each nameserver) and a
        # "lifetime" value (for the complete query).  We're happy with the
        # 2 second default timeout, but want to limit the overall query.
        self.queryObj.lifetime = dnstimeout

        # Use the package's caching system.
        self.queryObj.cache = dns.resolver.Cache()
        # For our custom NS lookups.
        self.ns_cache = {}
        # Except that we also want to cache failures, because we are
        # generally short-lived, and sometimes errors are slow to generate.
        self.failures = {}

    def lookup(self, question, qtype="A", ctype="IN", exact=False):
        """Do an actual lookup.  'question' should be the hostname or IP to
        query, and 'qType' should be the type of record to get (e.g. TXT,
        A, AAAA, PTR)."""
        rdtype = dns.rdatatype.from_text(qtype)
        rdclass = dns.rdataclass.from_text(ctype)
        try:
            return self.failures[question, rdtype, rdclass]
        except KeyError:
            pass
        reply = self.queryObj.cache.get((question, rdtype, rdclass))
        if not reply:
            try:
                reply = self.queryObj.query(question, rdtype, rdclass)
            except dns.resolver.NXDOMAIN:
                # This is actually a valid response, not an error condition.
                self.failures[question, rdtype, rdclass] = []
                return []
            except dns.exception.Timeout:
                # This may change next time this is run, so warn about that.
                log_method = getattr(self.logger, self.timeout_log_level)
                log_method("%s %s lookup timed out.", question, qtype)
                self.failures[question, rdtype, rdclass] = []
                return []
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
                if qtype not in ("MX", "AAAA", "TXT"):
                    # These indicate a problem with the nameserver.
                    self.logger.debug("%s %s lookup failed: %s", question,
                                      qtype, e)
                self.failures[question, rdtype, rdclass] = []
                return []
            except (ValueError, IndexError) as e:
                # A bad DNS entry.
                self.logger.warn("%s %s lookup failed: %s", question, qtype,
                                 e)
                self.failures[question, rdtype, rdclass] = []
                return []
            except struct.error as e:
                # A bad DNS entry.
                self.logger.warn("%s %s lookup failed: %s", question, qtype,
                                 e)
                self.failures[question, rdtype, rdclass] = []
                return []
        self.queryObj.cache.put((question, rdtype, rdclass), reply)
        if exact:
            return [i.to_text() for sublist in
                    (answer.to_rdataset().items
                     for answer in reply.response.answer
                     if answer.rdtype == rdtype and
                     answer.rdclass == rdclass) for i in sublist]
        return [i.to_text()
                for i in reply.response.answer[0].to_rdataset().items]

    _CNAME = dns.rdatatype.from_text("CNAME")
    _EXPECTED_FAILURES = (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.SyntaxError,
        ValueError,
        IndexError,
        struct.error,
        )
    def get_ns(self, domain, timeout=None):
        """Like query(domain, "NS"), but if the domain is a CNAME, then
        ask the domain's parent NS for the NS instead."""
        try:
            if self.failures[domain, "NS", "get_ns"]:
                return
        except KeyError:
            pass
        reply = self.ns_cache.get(domain)
        if reply:
            for i in reply:
                yield i
            return
        try:
            reply = self.queryObj.query(domain, rdtype="NS",
                                        raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            # This is actually a valid response, not an error condition.
            self.failures[domain, "NS", "get_ns"] = True
            return
        except dns.exception.Timeout:
            # This may change next time this is run, so warn about that.
            log_method = getattr(self.logger, self.timeout_log_level)
            log_method("%s NS lookup timed out.", domain)
            return
        except self._EXPECTED_FAILURES as e:
            self.logger.debug("%s NS lookup failed: %s", domain, e)
            return
        full_answer = []
        for answer in reply.response.answer:
            if answer.rdtype == self._CNAME:
                try:
                    parent = domain.split(".", 1)[1]
                    if not parent.endswith("."):
                        parent += "."
                    parent_ns = self.lookup(random.choice(
                        self.lookup(parent, "NS")))
                except IndexError:
                    self.logger.debug("%s NS lookup failed.", domain)
                    return
                if not parent_ns:
                    self.logger.debug("%s NS lookup has no parent.", domain)
                    return
                parent_resolver = dns.resolver.Resolver(configure=False)
                if timeout:
                    parent_resolver.lifetime = timeout
                parent_resolver.nameservers = parent_ns
                try:
                    parent_reply = parent_resolver.query(
                        domain, rdtype="NS", raise_on_no_answer=False)
                except dns.resolver.NXDOMAIN:
                    # This is actually a valid response, not an error condition.
                    self.failures[domain, "NS", "get_ns"] = True
                    return
                except dns.exception.Timeout:
                    # This may change next time this is run, so warn about that.
                    log_method = getattr(self.logger, self.timeout_log_level)
                    log_method("%s NS parent lookup timed out.", domain)
                    return
                except self._EXPECTED_FAILURES as e:
                    self.logger.debug("%s NS parent lookup failed: %s", domain, e)
                    return
                for parent_answer in parent_reply.response.additional:
                    part_answer = parent_answer.name.to_text()
                    yield part_answer
                    full_answer.append(part_answer)
            else:
                for i in answer.to_rdataset().items:
                    part_answer = i.to_text()
                    yield part_answer
                    full_answer.append(part_answer)
        self.ns_cache[domain] = full_answer


class _DNSCache(Cache):
    """Like the parent, but also knows about the combined DNSBL and URLBL
    that enable checking many DNSBL / URLBL with a single lookup.

    Use is transparent to the caller - i.e. they use the normal name for
    the list, and this class does the work of deciding whether to instead
    query the combined list.
    """

    def __init__(self, config_path=CONFIG_PATH):
        super(_DNSCache, self).__init__()
        # These are the lists that we combine (we don't combine everything,
        # because we can't combine white and black lists, and we don't
        # combine lists that return multiple results).
        # Note that DNSBL and URLBL are convenient labels, but DNSWL and
        # URLYL may also be also here.
        if os.path.exists(config_path):
            with open(config_path, "r") as fh:
                data = json.load(fh)
        else:
            data = {
              "COMBINED": "",
              "COMBINED_URL": "",
              "COMBINED_DNSBL": {},
              "COMBINED_DNSBL_REVERSE": {},
              "COMBINED_URLBL": {},
              "COMBINED_URLBL_REVERSE": {}
            }
        self.COMBINED = data["COMBINED"]
        self.COMBINED_URL = data["COMBINED_URL"]
        self.COMBINED_DNSBL = data["COMBINED_DNSBL"]
        self.COMBINED_DNSBL_REVERSE = data["COMBINED_DNSBL_REVERSE"]
        self.COMBINED_DNSBL_REVERSE_VALUES = \
            self.COMBINED_DNSBL_REVERSE.values()
        self.COMBINED_URLBL = data["COMBINED_URLBL"]
        self.COMBINED_URLBL_REVERSE = data["COMBINED_URLBL_REVERSE"]
        self.COMBINED_URLBL_REVERSE_VALUES = \
            self.COMBINED_URLBL_REVERSE.values()

    def lookup(self, question, qtype="A", ctype="IN", exact=False):
        """Do an actual lookup.  'question' should be the hostname or IP
        to query, and 'qType' should be the type of record to get
        (e.g. TXT, A, AAAA, PTR).

        If the lookup is within a domain that is handled by a combined
        list, then re-write the query so that it queries that list instead.
        We rely on the parent class caching the results so that when
        multiple lists in the combined system are queried, all but the
        first of these is pulled from the cache.

        When the question is not for one of the lists handled by
        a combined list the result is exactly the same as provided by
        Cache.lookup.
        When the question is one for one of the lists handled by
        a combined list, but the result indicates that the address is
        not listed, the result is an empty list.
        When the question is one for one of the lists handled by
        a combined list, and the result indicates that the address is
        listed, the result is always ["127.0.0.2"] - it is *not* the
        raw combined result.
        """
        logger = logging.getLogger("se-dns")
        rewrite_answer = None
        reverse_dict = None

        # XXX It would be better if this worked with any naming scheme.
        # Our lists always have 4 labels.
        # E.g: list1.dnsbl.example.com

        question_split = question.split(".")
        original_list = ".".join(question_split[-4:])
        address = ".".join(question_split[:-4])

        if (original_list in self.COMBINED_DNSBL_REVERSE_VALUES and
                self.COMBINED):
            logger.debug("Rewriting %s to use combined list.", question)
            rewrite_answer = original_list
            question = address + "." + self.COMBINED
            reverse_dict = self.COMBINED_DNSBL_REVERSE
        elif (original_list in self.COMBINED_URLBL_REVERSE_VALUES
              and self.COMBINED_URL):
            logger.debug("Rewriting %s to use url combined list.", question)
            rewrite_answer = original_list
            question = address + "." + self.COMBINED_URL
            reverse_dict = self.COMBINED_URLBL_REVERSE

        logger.debug("Looking up %s: %s", qtype, question)
        result = super(_DNSCache, self).lookup(question, qtype, ctype, exact)

        if rewrite_answer and result:
            for answer in result:
                if reverse_dict.get(answer) == rewrite_answer:
                    logger.debug("Converting %s from %s to ['127.0.0.2'] "
                                 "from %s.%s.", result, question, address,
                                 rewrite_answer)
                    result = ["127.0.0.2"]
                    break
            else:
                logger.debug("Ignoring %s from %s w.r.t. %s.%s", result,
                             question, address, rewrite_answer)
                result = []
        return result


# Central cache for all modules.
_DNS_CACHE = _DNSCache()


class DNSCache(object):
    """Proxy to the real DNSCache that allows per module timeouts."""

    def __init__(self, dnstimeout=10):
        self.dnsTimeout = dnstimeout
        self.COMBINED_DNSBL = _DNS_CACHE.COMBINED_DNSBL
        self.COMBINED_DNSBL_REVERSE = _DNS_CACHE.COMBINED_DNSBL_REVERSE
        self.COMBINED_DNSBL_REVERSE_VALUES = \
            _DNS_CACHE.COMBINED_DNSBL_REVERSE_VALUES
        self.COMBINED_URLBL = _DNS_CACHE.COMBINED_URLBL
        self.COMBINED_URLBL_REVERSE = _DNS_CACHE.COMBINED_URLBL_REVERSE
        self.COMBINED_URLBL_REVERSE_VALUES = \
            _DNS_CACHE.COMBINED_URLBL_REVERSE_VALUES

    def lookup(self, question, qtype="A", ctype="IN", exact=False):
        """Like Cache.lookup()"""
        # XXX This is not thread-safe
        _DNS_CACHE.queryObj.lifetime = self.dnsTimeout
        return _DNS_CACHE.lookup(question, qtype, ctype, exact)

    def get_ns(self, domain):
        """Like Cache.get_ns()"""
        # XXX This is not thread-safe
        _DNS_CACHE.queryObj.lifetime = self.dnsTimeout
        return _DNS_CACHE.get_ns(domain, self.dnsTimeout)
