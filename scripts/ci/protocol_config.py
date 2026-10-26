"""Mira module dependency selection from shared library recipes."""
from forgerecipes.configuration import make_config as catalog_config

def make_config():
    return catalog_config(('zlib', 'openssl', 'nghttp2', 'nghttp3', 'ngtcp2'))
