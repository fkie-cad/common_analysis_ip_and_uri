from .ip_and_uri_finder_analysis import CommonAnalysisIPAndURIFinder, IPFinder, URIFinder, system_version

__version__ = system_version

__all__ = [
    'IPFinder',
    'URIFinder',
    'CommonAnalysisIPAndURIFinder',
    '__version__'
]

analysis_class = CommonAnalysisIPAndURIFinder
