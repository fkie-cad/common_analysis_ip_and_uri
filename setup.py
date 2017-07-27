from setuptools import setup, find_packages
from common_analysis_ip_and_uri_finder import __version__


setup(
    name="common_analysis_ip_and_uri_finder",
    version=__version__,
    packages=find_packages(),
    install_requires=[
        'common_analysis_base',
        'common_helper_files',
        'yara-python >= 3.5'
    ],
    data_files=[('common_analysis_ip_and_uri_finder/yara_rules', [
        'common_analysis_ip_and_uri_finder/yara_rules/ip_rules.yara',
        'common_analysis_ip_and_uri_finder/yara_rules/uri_rules.yara',
        ])],
    dependency_links=[
        'git+https://github.com/mass-project/common_analysis_base.git#common_analysis_base',
        'git+https://github.com/fkie-cad/common_helper_files.git#common_helper_files'
    ],
    description="Analysis module to find IPs und URIs",
    author="Fraunhofer FKIE, University of Bonn Institute of Computer Science 4",
    license="GPL-3.0"
)
