from .ip_and_uri_finder_analysis import CommonAnalysisIPAndURIFinder
from .ip_and_uri_finder_analysis import IPFinder
from .ip_and_uri_finder_analysis import URIFinder

__all__ = [
    'IPFinder',
    'URIFinder',
    'CommonAnalysisIPAndURIFinder',
]

analysis_class = CommonAnalysisIPAndURIFinder
