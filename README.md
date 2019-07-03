[![PyPI](https://img.shields.io/pypi/v/se-dns.svg "PyPI")](https://pypi.python.org/pypi/se-dns)
[![TravisCI](https://img.shields.io/travis/SpamExperts/se-dns.svg?branch=master "TravisCI")](https://travis-ci.org/SpamExperts/se-dns)
[![Code Climate](https://codeclimate.com/github/SpamExperts/se-dns/badges/gpa.svg "Code Climate")](https://codeclimate.com/github/SpamExperts/se-dns)
[![Coveralls](https://coveralls.io/repos/SpamExperts/se-dns/badge.svg?branch=master&service=github  "Coveralls")](https://coveralls.io/github/SpamExperts/se-dns?branch=master)
[![pyup](https://pyup.io/repos/github/spamexperts/se-dns/shield.svg "Updates")](https://pyup.io/repos/github/spamexperts/se-dns/)
[![requires.io](https://requires.io/github/SpamExperts/se-dns/requirements.svg?branch=master "Requirements Status")](https://requires.io/github/SpamExperts/se-dns/requirements/?branch=master)

# se-dns 

A wrapper around dnspython.

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

The default config_path for these lists is hardcoded to `/etc/combined_lists.json`.
The config path has the following structure:

```json
{
  "COMBINED": "",
  "COMBINED_URL": "",
  "COMBINED_DNSBL": {},
  "COMBINED_DNSBL_REVERSE": {},
  "COMBINED_URLBL": {},
  "COMBINED_URLBL_REVERSE": {}
}
```

This code was originally based on the dnscache in SpamBayes.

# Installing notes
```
git clone git@github.com:Spamexperts/se-dns.git
cd se-dns/
pip install . --upgrade #
pip install -r requirements/tests.txt 
pip install -r requirements/base.txt 
```

# Testing
Create a script to retrieve the ip of a given hostname
```
"""All the imports make sure the package works in python3"""
import se_dns
from se_dns import dnsutil
from se_dns.dnsutil import DNSCache
import sys

"""This part should return the ipv4 of the hostname passed as parameter"""
look_up = DNSCache()
print(look_up.lookup(question=sys.argv[1]))
```

Execute the script

```python your_script.py example.com```

## Testing a branch ticket on this repository
You can find an example [here](https://jira.solarwinds.com/browse/MMA-869?focusedCommentId=1717412&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel#comment-1717412)
