#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

requirements = ["aiostream", "zmq", "pyre", "prompt_toolkit"]

setup_requirements = [ ]

test_requirements = [ ]

setup(
    author="Arun Sharma",
    author_email='arun@sharma-home.net',
    python_requires='>=3.5',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Raft implementation using ZRE and zmq",
    entry_points={
        'console_scripts': [
            'zre_raft=zre_raft.chat:main',
        ],
    },
    install_requires=requirements,
    license="MIT license",
    long_description=readme,
    include_package_data=True,
    keywords='zre_raft',
    name='zre_raft',
    packages=find_packages(include=['zre_raft', 'zre_raft.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/adsharma/zre_raft',
    version='0.1.0',
    zip_safe=False,
)
