import logging
import os
import socket

import yara
from common_analysis_base import AnalysisPluginFile
from common_helper_files import get_dir_of_file

from .version import __version__ as system_version

logger = logging.getLogger('CommonAnalysisIPAndURIFinder')
logger.setLevel(logging.INFO)


class FinderBase:
    @staticmethod
    def get_strings_from_matches(matches):
        # the desired strings are contained in the tuples at the third position in each yara match object
        return [item[2].decode() for match in matches for item in URIFinder.eliminate_overlaps(match.strings)]

    @staticmethod
    def get_file_content(file_path):
        with open(file_path, 'rb') as fd:
            return fd.read()


class IPFinder(FinderBase):
    def __init__(self, yara_ip_rules):
        self.ip_rules = yara.compile(yara_ip_rules)

    def _find_addresses_of_specific_format(self, string, address_format, validate=True):
        try:
            yara_matches = self.ip_rules.match(data=string)
        except Exception:
            logging.error('Could not match yara rules', exc_info=True)
            return []
        result = self.get_strings_from_matches(yara_matches)
        return self._validate_ips(result, address_format=address_format) if validate else result

    def find_ipv4_addresses(self, string, validate=True):
        return self._find_addresses_of_specific_format(string, socket.AF_INET, validate)

    def find_ipv6_addresses(self, string, validate=True):
        return self._find_addresses_of_specific_format(string, socket.AF_INET6, validate)

    def find_ips(self, string, validate=True):
        result = set()
        result.update(self.find_ipv4_addresses(string, validate=validate))
        result.update(self.find_ipv6_addresses(string, validate=validate))
        return list(result)

    def find_ipv4_addresses_in_file(self, file_path):
        file_content = self.get_file_content(file_path)
        return self.find_ipv4_addresses(file_content, validate=True)

    def find_ipv6_addresses_in_file(self, file_path):
        file_content = self.get_file_content(file_path)
        return self.find_ipv6_addresses(file_content, validate=True)

    def find_ips_in_file(self, file_path, validate=True):
        file_content = self.get_file_content(file_path)
        return self.find_ips(file_content, validate)

    @staticmethod
    def _validate_ip(ip, address_format):
        try:
            _ = socket.inet_pton(address_format, ip)
            return True
        except OSError:
            return False

    @staticmethod
    def _validate_ips(ip_list, address_format):
        return [ip for ip in ip_list[:] if IPFinder._validate_ip(ip, address_format)]


class URIFinder(FinderBase):
    def __init__(self, yara_uri_rules):
        self.rules = yara.compile(yara_uri_rules)

    def find_uris(self, uri_string):
        try:
            yara_matches = self.rules.match(data=uri_string)
        except Exception:
            logging.error('Could not match yara rules', exc_info=True)
            return []
        return self.get_strings_from_matches(yara_matches)

    def find_urls_in_file(self, file_path):
        file_content = self.get_file_content(file_path)
        return self.find_uris(file_content)

    @staticmethod
    def eliminate_overlaps(yara_match_strings):
        '''
        yara matches contain overlaps e.g. if the string contains 123.123.123.123
        the results would be 123.123.123.123, 23.123.123.123 and 3.123.123.123
        '''
        result = yara_match_strings[:]
        for i in range(1, len(yara_match_strings)):
            # if the matches are in direct succession
            if yara_match_strings[i][0] - yara_match_strings[i - 1][0] == 1:
                result.remove(yara_match_strings[i])
        return result


class CommonAnalysisIPAndURIFinder(AnalysisPluginFile):

    def __init__(self, yara_uri_rules=None, yara_ip_rules=None):
        super(CommonAnalysisIPAndURIFinder, self).__init__(system_version)
        self._set_rule_file_pathes(yara_uri_rules, yara_ip_rules)
        self._check_for_errors()

    def _set_rule_file_pathes(self, yara_uri_rules, yara_ip_rules):
        internal_signature_dir = os.path.join(get_dir_of_file(__file__), 'yara_rules')
        if yara_ip_rules is None:
            self.yara_ip_rules = os.path.join(internal_signature_dir, 'ip_rules.yara')
        else:
            self.yara_ip_rules = yara_ip_rules
        if yara_uri_rules is None:
            self.yara_uri_rules = os.path.join(internal_signature_dir, 'uri_rules.yara')
        else:
            self.yara_uri_rules = yara_uri_rules

    def _check_for_errors(self):
        if os.path.exists(self.yara_ip_rules):
            logging.debug(f'ip signature path: {self.yara_ip_rules}')
        else:
            logging.error(f'ip signatures not found: {self.yara_ip_rules}')
        if os.path.exists(self.yara_uri_rules):
            logging.debug(f'ip signature path: {self.yara_uri_rules}')
        else:
            logging.error(f'ip signatures not found: {self.yara_uri_rules}')

    def analyze_file(self, file_path, separate_ipv6=False):
        found_uris, found_ips_v4, found_ips_v6 = [], [], []
        if self.yara_uri_rules:
            found_uris = URIFinder(self.yara_uri_rules).find_urls_in_file(file_path)
        if self.yara_ip_rules:
            ip_finder = IPFinder(self.yara_ip_rules)
            found_ips_v4 = ip_finder.find_ipv4_addresses_in_file(file_path)
            found_ips_v6 = ip_finder.find_ipv6_addresses_in_file(file_path)
        report = self.prepare_analysis_report_dictionary()
        report['uris'] = found_uris
        if not separate_ipv6:
            report['ips'] = found_ips_v4 + found_ips_v6
        else:
            report['ips_v4'] = found_ips_v4
            report['ips_v6'] = found_ips_v6
        return report
