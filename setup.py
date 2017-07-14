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
    dependency_links=[
        'git+https://github.com/mass-project/common_helper_files.git#common_helper_files',
        'git+https://github.com/mass-project/common_analysis_base.git#common_analysis_base'
    ],
    description="Analysis module to find IPs und URIs",
    author="Fraunhofer FKIE, University of Bonn Institute of Computer Science 4",
    license="GPL-3.0"
)
