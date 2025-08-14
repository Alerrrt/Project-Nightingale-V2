import pytest

from backend.scanners.technology_fingerprint_scanner import TechnologyFingerprintScanner


def test_map_ecosystem_overrides_and_categories():
    scanner = TechnologyFingerprintScanner()
    # Direct override by tech name
    assert scanner._map_ecosystem('Django', ['web-frameworks']) == 'PyPI'
    assert scanner._map_ecosystem('Rails', ['web-frameworks']) == 'RubyGems'
    assert scanner._map_ecosystem('Spring', ['web-frameworks']) == 'Maven'
    # Category fallback
    assert scanner._map_ecosystem('SomeLib', ['javascript-libraries']) == 'npm'
    assert scanner._map_ecosystem('Ghost', ['blogs']) == 'npm'


def test_signature_extraction_basic():
    scanner = TechnologyFingerprintScanner()
    html = '''
    <html>
      <head>
        <meta name="generator" content="WordPress/6.4.1" />
        <script src="/assets/js/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.example.com/react-17.0.2.min.js"></script>
      </head>
    </html>
    '''
    headers = { 'Server': 'nginx/1.25.1', 'X-Powered-By': 'Express/4.18.2' }
    sigs = scanner._extract_signature_versions(html, {k.lower(): v for k, v in headers.items()})
    # meta generator
    assert 'wordpress' in sigs and '6.4.1' in sigs['wordpress']['versions']
    # scripts
    assert 'jquery' in sigs and '3.6.0' in sigs['jquery']['versions']
    assert 'react' in sigs and '17.0.2' in sigs['react']['versions']
    # headers
    assert 'nginx' in sigs and '1.25.1' in sigs['nginx']['versions']
    assert 'express' in sigs and '4.18.2' in sigs['express']['versions']


