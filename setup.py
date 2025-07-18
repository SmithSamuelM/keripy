#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
$ python setup.py register sdist upload

First Time register project on pypi
https://pypi.org/manage/projects/


Pypi Release
$ pip3 install twine

$ python3 setup.py sdist
$ twine upload dist/keri-0.0.1.tar.gz

Create release git:
$ git tag # lists all tags
$ git tag -a v0.6.11 -m "new feature"
$ git show v0.6.11
$ git push --tags # pushes tags to default remote
$ git push wot --tags   # pushes tags to wot remote

$ git tag -a v0.4.2 -m "bump version"
$ git push --tags
$ git checkout -b release_0.4.2
$ git push --set-upstream origin release_0.4.2
$ git checkout master

Best practices for setup.py and requirements.txt
https://caremad.io/posts/2013/07/setup-vs-requirement/
"""

from glob import glob
from os.path import basename
from os.path import splitext

from setuptools import find_packages, setup
setup(
    name='keri',
    version='2.0.0-dev3',  # also change in src/keri/__init__.py
    license='Apache Software License 2.0',
    description='Key Event Receipt Infrastructure',
    long_description="KERI Decentralized Key Management Infrastructure",
    author='Samuel M. Smith',
    author_email='smith.samuel.m@gmail.com',
    url='https://github.com/WebOfTrust/keripy',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    py_modules=[splitext(basename(path))[0] for path in glob('src/*.py')],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        # complete classifier list: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: Implementation :: CPython',
        # uncomment if you test on these interpreters:
        # 'Programming Language :: Python :: Implementation :: PyPy',
        # 'Programming Language :: Python :: Implementation :: IronPython',
        # 'Programming Language :: Python :: Implementation :: Jython',
        # 'Programming Language :: Python :: Implementation :: Stackless',
        'Topic :: Utilities',
    ],
    project_urls={
        'Documentation': 'https://keri.readthedocs.io/',
        'Changelog': 'https://keri.readthedocs.io/en/latest/changelog.html',
        'Issue Tracker': 'https://github.com/WebOfTrust/keripy/issues',
    },
    keywords=[
        # eg: 'keyword1', 'keyword2', 'keyword3',
    ],
    python_requires='>=3.13.2',
    install_requires=[
                        'lmdb==1.6.2',
                        'pysodium>=0.7.18',
                        'blake3>=1.0.5',
                        'msgpack>=1.1.0',
                        'cbor2>=5.6.5',
                        'multidict>=6.6.3',
                        'ordered-set>=4.1.0',
                        'hio>=0.7.14',
                        'multicommand>=1.0.0',
                        'jsonschema>=4.24.0',
                        'falcon>=4.0.2',
                        'hjson>=3.1.0',
                        'PyYaml>=6.0.2',
                        'apispec>=6.8.2',
                        'mnemonic>=0.21',
                        'PrettyTable>=3.16.0',
                        'http_sfv>=0.9.9',
                        'cryptography>=45.0.5',
                        'semver>=3.0.4',
                        'qrcode>=8.2',
                        'setuptools>=80.9.0',
                        'wheel>=0.45.1',
    ],
    extras_require={
    },
    tests_require=[
                    'coverage>=7.9.2',
                    'pytest>=8.4.1',
                    'pytest-shell>=0.3.2'
                  ],
    setup_requires=[
    ],
    entry_points={
        'console_scripts': [
            'keri_bob = keri.demo.demo_bob:main',
            'keri_eve = keri.demo.demo_eve:main',
            'keri_sam = keri.demo.demo_sam:main',
            'kli = keri.app.cli.kli:main',
            'klid = keri.app.cli.klid:main',
        ]
    },
)

