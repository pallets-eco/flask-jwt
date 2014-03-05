"""
Flask-JWT
=========

Flask-JWT is a Flask extension that adds basic Json Web Token features to any application.

Resources
---------

* `Documentation <http://packages.python.org/Flask-JWT/>`_
* `Issue Tracker <https://github.com/mattupstate/flask-jwt/issues>`_
* `Source <https://github.com/mattupstate/flask-jwt>`_
* `Development Version
  <https://github.com/mattupstate/flask-jwt/raw/develop#egg=Flask-JWT-dev>`_

"""

import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = [
            '--cov', 'flask_jwt',
            '--cov-report', 'term-missing',
            '--pep8'
        ]
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setup(
    name='Flask-JWT',
    version='0.1.0',
    url='https://github.com/mattupstate/flask-jwt',
    license='MIT',
    author='Matt Wright',
    author_email='matt@nobien.net',
    description='JWT token authentication for Flask apps',
    long_description=__doc__,
    packages=['flask_jwt'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=['Flask>=0.10.1', 'PyJWT>=0.1.8'],
    tests_require=['pytest', 'pytest-cov', 'pytest-pep8'],
    cmdclass={'test': PyTest},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
