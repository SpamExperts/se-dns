=======
History
=======

1.0.6 (2019-XX-XX)
------------------

* Avoid lookups with a double trailing dot in get_ns()
* Catch dns.exception.SyntaxError in get_ns().

1.0.5 (2019-05-03)
------------------

* Remove ``se_dns.dnstools``
* Add a "get_ns" method that queries for the NS record and works with CNAMEs.

1.0.4 (2017-05-26)
------------------

* Remove the requirement for the configuration file to exist.

1.0.3 (2017-05-26)
------------------

* Refactor code to load urlbl combined lists from a .json file
* Add cache to local_ip_addresses
