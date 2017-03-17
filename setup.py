import sys
from setuptools import setup

import dnsagent


if sys.version_info[:2] < (3, 4):
    raise SystemExit('require Python3.4+')


setup(
    name='dnsagent',
    version=dnsagent.__version__,
    packages=['dnsagent'],
    install_requires=[
        'iprir>=0.1.2.dev0',
        'twisted>=16',
        'watchdog>=0.8',
        'zope.interface',
    ],
    extras_require={
        ':python_version<"3.5"': ['typing'],
        'windows': ['pypiwin32'],   # twisted dependancy
    },
    python_requires='>=3.4',
    url='https://github.com/account-login/dnsagent',
    license='MIT',
    author='account-login',
    author_email='',
    description='A configurable dns proxy powered by twisted.',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: Twisted',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        'Operating System :: OS Independent',
        'Framework :: Twisted',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='dns proxy twisted',
    zip_safe=False,
)
