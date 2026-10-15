"""Offline, heuristic phishing email analyzer. Python 3.9+; no external dependencies."""
import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

URGENT = [r'urgent', r'act now', r'immediately', r'within 24 hours', r'account (?:will be )?suspend', r'verify your account', r'password expires', r'confirm your identity']
BRANDS = {'paypal.com', 'microsoft.com', 'google.com', 'amazon.com', 'apple.com'}

class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.text = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            link = dict(attrs).get('href', '')
            if link:
                self.links.append(link)
    def handle_data(self, data):
        self.text.append(data)

def domain_of(address):
    email_address = parseaddr(address)[1]
    return email_address.rsplit('@', 1)[-1].lower().rstrip('.') if '@' in email_address else ''

def host_of(url):
    try:
        return (urlsplit(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''

def extract_body(msg):
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == 'attachment':
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        try:
            content = part.get_content()
        except (UnicodeError, LookupError):
            continue
        (html if part.get_content_type() == 'text/html' else plain).append(str(content))
    parser = HTMLLinks()
    for page in html:
        parser.feed(page)
    return '\n'.join(plain + parser.text), parser.links

def analyze(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    sender = str(msg.get('From', ''))
    from_domain = domain_of(sender)
    return_path = str(msg.get('Return-Path', ''))
    return_domain = domain_of(return_path)
    auth_headers = [str(x) for x in msg.get_all('Authentication-Results', [])]
    received_spf = [str(x) for x in msg.get_all('Received-SPF', [])]
    auth = ' '.join(auth_headers + received_spf).lower()
    text, html_links = extract_body(msg)
    subject = str(msg.get('Subject', ''))
    full_text = subject + '\n' + text
    urls = re.findall(r'https?://[^\s<>"\']+', full_text, flags=re.I) + html_links
    urls = list(dict.fromkeys(unescape(u).rstrip('.,);') for u in urls))
    findings = []
    score = 0
    def flag(reason, points):
        nonlocal score
        findings.append({'indicator': reason, 'points': points})
        score += points
    for method in ('spf', 'dkim', 'dmarc'):
        # These are reported results, not independent verification.
        if re.search(r'\b' + method + r'\s*=\s*(fail|softfail|permerror)', auth):
            flag(method.upper() + ' reported failure', 25 if method != 'dmarc' else 30)
    if from_domain and return_domain and from_domain != return_domain:
        flag('From / Return-Path domain mismatch (may be legitimate)', 10)
    if not auth_headers and not received_spf:
        flag('No authentication result headers available', 5)
    if not msg.get_all('Received'):
        flag('No Received headers available', 5)
    matches = [p for p in URGENT if re.search(p, full_text, flags=re.I)]
    if matches:
        flag('Urgent or coercive wording (' + str(len(matches)) + ' patterns)', min(20, len(matches) * 5))
    for url in urls[:30]:
        host = host_of(url)
        if not host:
            flag('Malformed or unparsable link', 10)
            continue
        if url.lower().startswith('http://'):
            flag('Unencrypted HTTP link: ' + host, 10)
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host):
            flag('Link uses IP address: ' + host, 15)
        if '@' in urlsplit(url).netloc:
            flag('URL uses @ in authority: ' + host, 15)
        if host.startswith('xn--') or '.xn--' in host:
            flag('Internationalized/punycode hostname: ' + host, 10)
        for brand in BRANDS:
            brand_word = brand.split('.')[0]
            if brand_word in host and host != brand and not host.endswith('.' + brand):
                flag('Possible brand impersonation in link: ' + host, 20)
                break
    score = min(100, score)
    return {
        'subject': subject, 'from': sender, 'from_domain': from_domain,
        'return_path': return_path, 'return_path_domain': return_domain,
        'received_headers': len(msg.get_all('Received', [])),
        'authentication_results': auth_headers, 'received_spf': received_spf,
        'dkim_signature_present': bool(msg.get('DKIM-Signature')),
        'links': urls, 'risk_score': score,
        'risk_level': 'HIGH' if score >= 60 else 'MEDIUM' if score >= 30 else 'LOW',
        'findings': findings,
        'limitations': 'Heuristic screening only. Authentication-Results are not independently verified; domain alignment is simplified. A low score does not prove safety.'
    }

def main():
    ap = argparse.ArgumentParser(description='Analyze a saved .eml email for phishing indicators')
    ap.add_argument('email_file', type=Path)
    ap.add_argument('--output', type=Path, default=Path('audit_report.json'))
    args = ap.parse_args()
    result = analyze(args.email_file.read_bytes())
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print('Risk:', result['risk_level'], '(' + str(result['risk_score']) + '/100)')
    for f in result['findings']:
        print('-', f['indicator'], '(+' + str(f['points']) + ')')
    print('Saved audit:', args.output)

if __name__ == '__main__':
    main()
