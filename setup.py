#! /usr/bin/env python

from __future__ import absolute_import

import se_dns
import setuptools

REQUIRES = ["dnspython"]
DESCRIPTION = """Simple dns tools."""

CLASSIFIERS = [
    "Operating System :: POSIX",
    "Programming Language :: Python",
    "Intended Audience :: System Administrators",
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
]

setuptools.setup(
    name='se-dns',
    description=DESCRIPTION,
    author="SpamExperts",
    use_scm_version={
        "write_to": "se_dns/__init__.py",
        'write_to_template': '__version__ = "{version}"\n',
        'tag_regex': r'^(?P<prefix>v)?(?P<version>[^\+]+)(?P<suffix>.*)?$',
        'version_scheme': lambda version: version.tag.public,
        'local_scheme': lambda x: ""
    },
    setup_requires=['setuptools_scm'],
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
