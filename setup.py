from setuptools import setup
import sys

NAME = 'common_analysis_ip_and_uri_finder'


def _get_version():
    sys.path.append(NAME)
    from version import __version__
    return __version__


setup(
    name=NAME,
    version=_get_version(),
    packages=[NAME],
    package_dir={NAME: NAME},
    package_data={NAME: ['yara_rules/*']},
    install_requires=[
        'common_analysis_base @ git+https://github.com/mass-project/common_analysis_base.git',
        'common_helper_files @ git+https://github.com/fkie-cad/common_helper_files.git',
        'packaging >= 23.0',
        'yara-python >= 3.5',
    ],
    extras_require={
        'dev': [
            'pytest',
            'pytest-pycodestyle',
            'pytest-cov'
        ]
    },
    data_files=[('common_analysis_ip_and_uri_finder/yara_rules', [
        'common_analysis_ip_and_uri_finder/yara_rules/ip_rules.yara',
        'common_analysis_ip_and_uri_finder/yara_rules/uri_rules.yara',
    ])],
    description='Analysis module to find IPs und URIs',
    author='Fraunhofer FKIE, University of Bonn Institute of Computer Science 4',
    license='GPL-3.0'
)
