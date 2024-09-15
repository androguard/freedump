import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "freedump",
    version = "0.0.1",
    author = "ping2A",
    author_email = "ping@42.bzh",
    description = ("A quick python library to write and read live (frida) or dumped memory."),
    license = "GPL3",
    keywords = "memory dump frida",
    url = "http://packages.python.org/freedump",
    packages=['freedump'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
)
