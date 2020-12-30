from setuptools import setup, find_packages

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='netbox-sync-physical-hosts',
    version='0.1.0',
    author='guanana2',
    author_email='guanana2@gmail.com',
    packages=find_packages(),
    url='http://pypi.python.org/pypi/netbox-sync-physical-hosts/',
    license='LICENSE',
    description='Because automated source of truth can be handy sometimes ;-)',
    long_description=open('README.md').read(),
    install_requires=required
)
