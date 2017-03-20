#! /usr/bin/env python

from __future__ import absolute_import

import se_dns
import distutils.core

REQUIRES = ["dnspython"]
DESCRIPTION = """Simple dns tools."""

CLASSIFIERS = [
    "Operating System :: POSIX",
    "Programming Language :: Python",
    "Intended Audience :: System Administrators",
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
]

distutils.core.setup(
    name='se-dns',
    description=DESCRIPTION,
    author="SpamExperts",
    version=se_dns.__version__,
    license='GPL',
    platforms='POSIX',
    keywords='server',
    classifiers=CLASSIFIERS,
    # scripts=[],
    install_requires=REQUIRES,
    packages=[
        'se_dns',
    ],
)
