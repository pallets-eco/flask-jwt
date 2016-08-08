"""
Flask-JWT
=========

Flask-JWT is a Flask extension that adds basic Json Web Token features to any
application.

Resources
---------

* `Documentation <http://packages.python.org/Flask-JWT/>`_
* `Issue Tracker <https://github.com/mattupstate/flask-jwt/issues>`_
* `Source <https://github.com/mattupstate/flask-jwt>`_
* `Development Version
  <https://github.com/mattupstate/flask-jwt/raw/develop#egg=Flask-JWT-dev>`_

"""

import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


def get_requirements(suffix=''):
    with open('requirements%s.txt' % suffix) as f:
        rv = f.read().splitlines()
    return rv


def get_long_description():
    with open('README.rst') as f:
        rv = f.read()
    return rv


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = [
            '-xrs',
            '--cov', 'flask_jwt',
            '--cov-report', 'term-missing',
            '--pep8',
            '--flakes',
            '--clearcache',
            'tests'
        ]
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setup(
    name='Webstack-Flask-JWT',
    version='0.3.3',
    url='https://github.com/webstack/flask-jwt',
    license='MIT',
    author='Matt Wright',
    author_email='matt@nobien.net',
    description='JWT token authentication for Flask apps',
    long_description=__doc__,
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=get_requirements(),
    tests_require=get_requirements('-dev'),
    cmdclass={'test': PyTest},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
