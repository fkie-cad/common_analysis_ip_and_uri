from setuptools import setup
from common_analysis_ip_and_uri_finder import __version__
from setuptools.command.install import install
from common_helper_process import execute_shell_command

"""This setup.py needs to be executed with sudo -EH python3 setup.py install"""
class BashScript(install):
    def run(self):
        command = 'sudo -EH bash install_geo_ip.sh'
        print(execute_shell_command(command))
        install.run(self)

setup(
    name="common_analysis_ip_and_uri_finder",
    version=__version__,
    packages=['common_analysis_ip_and_uri_finder'],
    package_dir={'common_analysis_ip_and_uri_finder': 'common_analysis_ip_and_uri_finder'},
    package_data={'common_analysis_ip_and_uri_finder': ['yara_rules/*']},
    install_requires=[
        'common_analysis_base >= 0.1',
        'common_helper_files >= 0.2',
        'yara-python >= 3.5'
    ],
    data_files=[('common_analysis_ip_and_uri_finder/yara_rules', [
        'common_analysis_ip_and_uri_finder/yara_rules/ip_rules.yara',
        'common_analysis_ip_and_uri_finder/yara_rules/uri_rules.yara',
    ])],
    dependency_links=[
        'https://github.com/mass-project/common_analysis_base/tarball/master#egg=common_analysis_base-0.1',
        'https://github.com/fkie-cad/common_helper_files/tarball/master#egg=common_helper_files-0.2'
    ],
    cmdclass={
        'install': BashScript,
    },
    description="Analysis module to find IPs und URIs",
    author="Fraunhofer FKIE, University of Bonn Institute of Computer Science 4",
    license="GPL-3.0"
)
