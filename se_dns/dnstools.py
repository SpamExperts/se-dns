import os
import pwd
import time
import socket
import ipaddr
import pickle
import urllib2
import urlopen
import httplib
import subprocess

from dnsutil import DNSCache
import se_dns

DNS_CACHE = DNSCache()


def local_ip_addresses(cache_fn, include_external=False, use_cached=False,
                       logger=None):
    """Get all the IP addresses in use on this server.

    This calls an external process, so should be used lightly.
    """
    if use_cached:
        try:
            cache_good = time.time() - os.stat(cache_fn).st_mtime < 60 * 60 * 24
        except (OSError, EOFError, IOError) as e:
            if logger:
                logger.debug("Not using cache: %s", e)
            cache_good = False
        if cache_good:
            with open(cache_fn) as cache_file:
                try:
                    result = pickle.load(cache_file)
                except (OSError, EOFError, IOError) as e:
                    if logger:
                        logger.warn("Bad local IP address cache; replacing.")
                else:
                    if logger:
                        logger.debug("Using cache for local IP addresses.")
                    return result
        elif logger:
            logger.debug("Not using cache for local IP addresses.")
    ips = set()
    # XXX Once we are using psutil 3.0+, we should switch to using that
    # XXX rather than this fairly fragile subprocess.
    # XXX e.g. for IPv4: [addr.address
    # XXX                 for key, addrs in psutil.net_if_addrs().iteritems()
    # XXX                 if key != 'lo'
    # XXX                 for addr in addrs if addr.family==socket.AF_INET]
    # XXX and IPv6 the same, but socket.AF_INET6.
    cmd_templ = ("/sbin/ifconfig | grep '[[:space:]]inet[[:space:]]' "
                 "| grep -v '127.0.0.1' | "
                 "awk '{ print $2 }'")
    ip_list = subprocess.Popen(
        cmd_templ, shell=True, stdout=subprocess.PIPE,
        stdin=subprocess.PIPE).communicate()[0].strip()
    if ip_list:
        ips.update([ip for ip in ip_list.split()])
    cmd_templ = ("/sbin/ifconfig | grep '[[:space:]]inet6[[:space:]]' | "
                 "grep -i global | awk '{ print $2 }'")
    ip_list = subprocess.Popen(
        cmd_templ, shell=True, stdout=subprocess.PIPE,
        stdin=subprocess.PIPE).communicate()[0].strip()
    if ip_list:
        ips.update([ip.split("/", 1)[0] for ip in ip_list.split()])
    if include_external:
        req = urllib2.Request(include_external,
                              headers={"User-Agent": "se_dns/%s " %
                                       se_dns.__version__})
        try:
            local_ip = urlopen(req, timeout=5).read().strip()
        except (socket.error, socket.timeout, urllib2.URLError,
                httplib.HTTPException) as e:
            if logger:
                logger.warn("Unable to retrieve external IP: %s", e)
        else:
            if local_ip.startswith("::ffff:"):
                # This is junk that nginx adds to IPv4 addresses.
                local_ip = local_ip.rsplit(":", 1)[1]
            ips.add(local_ip)
    # No longer add data to ips, we can convert it to a list to serialize it
    ips = list(ips)
    if logger:
        logger.info("Local IP addresses: %s", ", ".join(ips))
    adjust_cache = not os.path.exists(cache_fn)
    try:
        with open(cache_fn, "wb") as cache_file:
            pickle.dump(ips, cache_file, pickle.HIGHEST_PROTOCOL)
    except (IOError, OSError) as e:
        if logger:
            logger.warn("Unable to cache IP list: %s", e)
    else:
        # XXX This should not have the users hard-coded.
        if adjust_cache:
            # The cache might be created by the API (www-data), local_scan
            # (Debian-exim), or setup/update (root).  Ensure that everyone
            # can work with it.  The www-data user is in the Debian-exim
            # group.
            try:
                os.chmod(cache_fn, 0o660)
            except OSError as e:
                if logger:
                    logger.info("Unable to set permissions of cache: %s", e)
            try:
                os.chown(cache_fn, os.geteuid(),
                         pwd.getpwnam("Debian-exim").pw_gid)
            except (OSError, IOError) as e:
                if logger:
                    logger.info("Unable to set owner/group of cache: %s", e)
    return list(set(ips))


def name_to_ip(name, prefer_ipv6=True):
    """Basically like socket.gethostbyname(), except that it also supports
    IPv6.  The caller is responsible for setting an appropriate timeout and
    handling any errors."""
    ipv4 = None
    ipv6 = None
    # XXX We really want a timeout on this somehow.  Can we do this
    # XXX differently to make that possible?  We don't want to use
    # XXX signals, because that causes issues with Exim.  We could use
    # XXX a subprocess or thread, although that's a bit ugly.
    for (family, socktype, proto, canonname,
         sockaddr) in socket.getaddrinfo(name, None):
        if family == socket.AF_INET6:
            ipv6 = sockaddr[0]
            if prefer_ipv6:
                return ipv6
        elif family == socket.AF_INET:
            ipv4 = sockaddr[0]
    return ipv4 or ipv6


def hosts_equal(host1, host2, cache_fn, skip_getaddrinfo=False, logger=None,
                external_link=None):
    """Return True if these are the same physical machine."""
    if host1 == host2:
        return True
    # Currently we just check if the hosts resolve to the same IP, with
    # some special-casing for localhost.
    hostname = socket.gethostname()
    host1_is_ip = False
    host2_is_ip = False
    try:
        ip1 = ipaddr.IPAddress(host1)
    except ValueError:
        if host1 == "localhost":
            host1 = hostname
        ip1 = None
    else:
        if ip1.is_loopback or (hasattr(ip1, "site_local") and ip1.site_local):
            host1 = hostname
        else:
            host1_is_ip = True
    try:
        ip2 = ipaddr.IPAddress(host2)
    except ValueError:
        if host2 == "localhost":
            host2 = hostname
        ip2 = None
    else:
        if ip2.is_loopback or (hasattr(ip2, "site_local") and ip2.site_local):
            host2 = hostname
        else:
            host2_is_ip = True
    # Try DNS lookups first.
    host1_ips = []
    host1_has_ipv6 = False
    if not host1_is_ip:
        host1_ips.extend(DNS_CACHE.lookup(host1, "A", exact=True))
        host1_aaaa = DNS_CACHE.lookup(host1, "AAAA", exact=True)
        if host1_aaaa:
            host1_ips.extend(host1_aaaa)
            host1_has_ipv6 = True
    if ip1:
        host1_ips.append(str(ip1))
    if host1 == hostname:
        host1_ips.extend(local_ip_addresses(cache_fn, include_external=external_link,
                                            use_cached=True, logger=logger))
    host2_ips = []
    if not host2_is_ip:
        host2_ips.extend(DNS_CACHE.lookup(host2, "A", exact=True))
        if host1_has_ipv6:
            # If host1 doesn't have any AAAA records, then there's no
            # point trying to find any matching ones from host2.
            host2_ips.extend(DNS_CACHE.lookup(host2, "AAAA", exact=True))
    if ip2:
        host2_ips.append(str(ip2))
    if host2 == hostname:
        host2_ips.extend(local_ip_addresses(cache_fn, include_external=external_link,
                                            use_cached=True, logger=logger))
    if set(host1_ips).intersection(set(host2_ips)):
        return True
    if skip_getaddrinfo:
        return False
    # Fall back to getaddrinfo.
    try:
        if host1_is_ip:
            host1_ip = host1
        else:
            host1_ip = name_to_ip(host1)
        if host2_is_ip:
            host2_ip = host2
        else:
            host2_ip = name_to_ip(host2)
        return host1_ip == host2_ip
    except (socket.error, UnicodeError):
        return False
