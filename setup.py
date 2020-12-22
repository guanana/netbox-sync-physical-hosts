from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='netbox-sync-physical-hosts',
    version='0.1.0',
    author='guanana2',
    author_email='guanana2@gmail.com',
    packages=['netbox-sync-physical-hosts',
              'netbox-sync-physical-hosts.tests',
              'netbox-sync-physical-hosts.modules',
              'netbox-sync-physical-hosts.netboxhandler'],
    url='http://pypi.python.org/pypi/netbox-sync-physical-hosts/',
    license='LICENSE',
    description='Because automated source of truth can be handy sometimes ;-)',
    long_description=open('README.md').read(),
    install_requires=required
)
