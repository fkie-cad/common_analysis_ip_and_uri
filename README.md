# Common Analysis IP and URI finder

"Strings. But only IPs and URIs" -- No one

---------------

Detects IPv4-addresses, IPv6-addresses and URIs on files (incl. text files).

## Example usage

```python
from common_analysis_ip_and_uri_finder import CommonAnalysisIPAndURIFinder


file_path = '/path/to/some/file'
finder = CommonAnalysisIPAndURIFinder()

print(finder.analyze_file(file_path))
{
    "plugin_version": "0.4.2",
    "analysis_date": datetime.datetime(2023, 2, 8, 14, 43, 7, 700948),
    "uris": [
        "https://github.com/fkie-cad/FACT_core.git",
        "http://localhost:5000/rest/firmware/e692eca8505b0f4a3572d4d42940c6d5706b8aabec6ad1914bd4d733be9dfecf_25221120",
        "https://registry.npmjs.org/vis-network/-/vis-network-8.5.2.tgz",
        "tcp://localhost:4840",
        "tcp://efca59cf196b:4840",
        "https://github.com/node-opcua/node-opcua",
        "https://github.com/node-opcua/node-opcua",
        "https://github.com/node-opcua/node-opcua",
        "http://141.30.62.26",
        "https://github.com/ReFirmLabs/binwalk.git",
        "https://github.com/ReFirmLabs/binwalk",
        "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        "https://chromium.googlesource.com/chromium/tools/depot_tools.git",
        "https://github.com/CTFd/CTFd.git",
        "https://github.com/fkie-cad/FirmwareScraper",
        "https://www.youtube.com/watch",
        "https://github.com/pypa/virtualenv",
        "https://github.com/fkie-cad/common_helper_unpacking_classifier.git",
        "https://github.com/fkie-cad/common_helper_extraction.git",
        "https://github.com/mass-project/common_analysis_base.git",
        "https://github.com/fkie-cad/common_helper_files.git"
    ],
    "ips": [
        "1.0.0.54",
        "4.0.42.104",
        "4.3.28.113",
        "1.9.3.50",
        "127.0.0.1",
        "127.0.0.1",
        "127.0.0.1",
        "192.168.2.3",
        "192.168.0.100",
        "141.30.62.26",
        "5.4.0.86",
        "4.0.86.90",
        "5.4.0.86",
        "4.0.86.90",
        "127.0.0.1",
        "127.0.0.1",
        "::ffff:172",
        "face::",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:172.17.0.2",
        "::ffff:172.17.0.2"
    ]
}
```

## Development

The API is simple enough to adapt to different purposes. De-duplication would be a possibility - ideally as optional parameter. You can try to improve the analysis by working on the yara rule files found in `common_analysis_ip_and_uri_finder/yara_rules`.

## Requirements
* [YARA](https://virustotal.github.io/yara/)
