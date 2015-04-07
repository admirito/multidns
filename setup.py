#!/usr/bin/env python

from setuptools import setup, find_packages, Command

from multidns import __doc__ as long_description
from multidns import __version__ as version

class GenerateReadme(Command):
    description = "Generates README file from long_description"
    user_options = []
    def initialize_options(self): pass
    def finalize_options(self): pass
    def run(self):
        open("README","w").write(long_description)

setup(
    name = "multidns",
    version = version,
    description = "relay DNS requests to multiple servers and returns "
                  "the fastest answer",
    long_description=long_description,
    url = "",
    cmdclass = {"readme": GenerateReadme},
    author = "Mohammad Razavi",
    author_email = "mrazavi64@gmail.com",
    license = "GPL",
    classifiers = ["Topic :: Internet :: Name Service (DNS)",
                    "Programming Language :: Python :: 2",
                    "Programming Language :: Python :: 3",
                  ],
    keywords = "dns iran filtering",
    py_modules = ["multidns"],
    #packages = find_packages(),
    install_requires = ["dnslib"],
    entry_points = {
        "console_scripts": [
            "multidns=multidns:main",
        ],
    },
)
