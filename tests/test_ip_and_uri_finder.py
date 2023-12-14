import unittest
import os
import tempfile
import socket

from common_analysis_ip_and_uri_finder import IPFinder, URIFinder


def find_file(name, root='.'):
    file_path = None
    for path, dirnames, filenames in os.walk(root):
        for filename in filenames:
            if filename == name:
                return os.path.join(path, filename)
    return file_path


class TestIpAndUrlFinder(unittest.TestCase):
    def setUp(self):
        self.yara_uri_rules = find_file('uri_rules.yara')
        self.yara_ip_rules = find_file('ip_rules.yara')
        self.test_string = "1.2.3.4 abc 123.123.123.123 abc 1.2.3 .4 abc 1.1234.1.1 abc 1.a.1.1 1234:1234:abcd:abcd:1234:1234:abcd:abcd 2001:db8:0:8d3:0:8a2e:70:7344 "

    def test_find_ips(self):
        results = IPFinder(self.yara_ip_rules).find_ips(self.test_string, validate=False)
        expected_results = {"1.2.3.4", "123.123.123.123", "1234:1234:abcd:abcd:1234:1234:abcd:abcd",
                            "2001:db8:0:8d3:0:8a2e:70:7344"}
        assert set(results) == expected_results

    def test_find_ipv4_addresses(self):
        results = IPFinder(self.yara_ip_rules).find_ipv4_addresses(self.test_string, validate=True)
        expected_results = {"1.2.3.4", "123.123.123.123"}
        assert set(results) == expected_results

    def test_find_ipv6_addresses(self):
        results = IPFinder(self.yara_ip_rules).find_ipv6_addresses(self.test_string, validate=True)
        expected_results = {"1234:1234:abcd:abcd:1234:1234:abcd:abcd", "2001:db8:0:8d3:0:8a2e:70:7344"}
        assert set(results) == expected_results

    def test_find_ips_in_file(self):
        with tempfile.NamedTemporaryFile() as test_file:
            test_file.write(
                b"""1.2.3.4
                abc
                255.255.255.255
                1234:1234:abcd:abcd:1234:1234:abcd:abcd"""
            )
            test_file.seek(0)
            results = set(IPFinder(self.yara_ip_rules).find_ips_in_file(test_file.name, validate=False))
        expected_results = {"1.2.3.4", "255.255.255.255", "1234:1234:abcd:abcd:1234:1234:abcd:abcd"}
        assert results == expected_results

    def test_validate_ipv4(self):
        ips = ["1.1.1.1", "1.1.1", "a.1.1.1", "1.1.1.1.1"]
        valid_ips = ["1.1.1.1"]
        validated_ips = IPFinder(self.yara_ip_rules)._validate_ips(ips, socket.AF_INET)
        assert validated_ips == valid_ips

    def test_validate_ipv6(self):
        ips = ["1234:1234:abcd:abcd:1234:1234:1.0.0.127", "2001:db8::8d3::", "2001:db8:0:0:8d3::"]
        valid_ips = ['1234:1234:abcd:abcd:1234:1234:1.0.0.127', "2001:db8:0:0:8d3::"]
        validated_ips = IPFinder(self.yara_ip_rules)._validate_ips(ips, socket.AF_INET6)
        assert validated_ips == valid_ips

    def test_find_uri(self):
        test_string = "http://www.google.de https://www.test.de/test/ " \
                      "ftp://ftp.is.co.za/rfc/rfc1808.txt telnet://192.0.2.16:80/"
        test_result = set(URIFinder(self.yara_uri_rules).find_uris(test_string))
        expected_result = {"http://www.google.de", "https://www.test.de/test/", "ftp://ftp.is.co.za/rfc/rfc1808.txt",
                           "telnet://192.0.2.16:80/"}
        assert test_result == expected_result
