import re
from urllib.parse import urlparse
from tld import get_tld

def having_ip_address(url):
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])', url)
    return 1 if match else 0

def abnormal_url(url):
    try:
        parsed = urlparse(url)
        return 0 if re.search(re.escape(parsed.hostname or ''), url) else 1
    except:
        return 0

def count_dot(url): return url.count('.')
def count_www(url): return url.count('www')
def count_atrate(url): return url.count('@')
def no_of_dir(url): return urlparse(url).path.count('/')
def no_of_embed(url): return urlparse(url).path.count('//')

def shortening_service(url):
    pattern = r"(bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|tinyurl|t\.co|tr\.im|is\.gd)"
    return 1 if re.search(pattern, url) else 0

def count_https(url): return url.count('https')
def count_http(url): return url.count('http')
def count_per(url): return url.count('%')
def count_ques(url): return url.count('?')
def count_hyphen(url): return url.count('-')
def count_equal(url): return url.count('=')
def url_length(url): return len(url)
def hostname_length(url): return len(urlparse(url).netloc)

def suspicious_words(url):
    return 1 if re.search(r'(paypal|login|signin|bank|account|update|free|lucky|bonus)', url, re.IGNORECASE) else 0

def digit_count(url): return sum(c.isdigit() for c in url)
def letter_count(url): return sum(c.isalpha() for c in url)

def fd_length(url):
    try: return len(urlparse(url).path.split('/')[1])
    except: return 0
