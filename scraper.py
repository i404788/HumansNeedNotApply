from cloudscraper import create_scraper
from diskcache import FanoutCache
from bs4 import BeautifulSoup
from typing import NamedTuple, Union, Set, List
from urllib.parse import urlparse
import copyreg, ssl
import re

url_pattern = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
domain_pattern = re.compile('^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$')

def save_sslcontext(obj):
    return obj.__class__, (obj.protocol,)
 
copyreg.pickle(ssl.SSLContext, save_sslcontext)

class RequestManager:
    def __init__(self, db_path='db'):
        self.gdb = FanoutCache(db_path)
        self.db = self.gdb.cache('RequestManager')
        # Load previous cloudflare instance
        if self.db.get('scraper', None):
            self.scraper = self.db['scraper']
        else:
            self.scraper = create_scraper()

    def get(self, url, *args, **kwargs):
        try:
            r = self.scraper.get(url, *args, **kwargs);
            self.db['scraper'] = self.scraper
        except Exception:
            r = RequestShim(404)
        return r

class RequestShim(NamedTuple):
    status_code: int

class ScrapeItem(NamedTuple):
    itype: str
    uri: str
    tags: Union[Set[str], None] = None
    stack: List[str] = []

def norm_url(path_or_url: str, domain: str=''):
    # try:
    #     o = urlparse(uri)
    if path_or_url[0] in '/?#':
        # Assume relative url
        return f'http://{domain}{path_or_url}'
    elif '://' in path_or_url:
        if path_or_url.startswith('://'):
            # Some websites use scheme-less URIs
            path_or_url = 'http' + path_or_url
        # Assume scheme and domain already filled in
        return path_or_url
    else:
        # Missing scheme
        return f'http://{path_or_url}'

def extract_urls(text: str, domain: str):
    b = BeautifulSoup(text)
    urls = set()
    for link in b.find_all('a'):
        if link.get('href', None):
            urls.add(norm_url(link['href'], domain))

    urls = urls.union(re.findall(url_pattern, text))
    return urls


class Scraper:
    def __init__(self, req_manager: RequestManager, db_path='db', item_filter = lambda item: True):
        self.rm = req_manager
        self.gdb = FanoutCache(db_path)
        self.filter = item_filter

        # Future pages to scrape (mostly FIFO)
        self.deque = self.gdb.deque('Scraper-deque')
        self.results = self.gdb.cache('Scraper-results')
        
        # After pages are finished, domains is excluded
        self.excluded_domains = self.gdb.get('excluded_domains', set())
        self.excluded_pages = self.gdb.get('excluded_pages', set())

    def enqueue(self, item: ScrapeItem):
        self.deque.append(item)

    def enqueue_front(self, item: ScrapeItem):
        self.deque.appendleft(item)
    
    def check_exclusion(self, item: ScrapeItem):        
        exclusion_set = self.gdb.get(f'excluded_{item.itype}', set())
        # TODO: Monitor skipped, queue size & completed size
        return item.uri in exclusion_set

    def add_exclusion(self, item: ScrapeItem):
        exclusion_set = self.gdb.get(f'excluded_{item.itype}', set())
        exclusion_set.add(item.uri)
        self.gdb[f'excluded_{item.itype}'] = exclusion_set

    def has_next(self):
        return len(self.deque) > 0

    def next(self):
        item = self.deque.popleft()
        
        if not self.filter(item):
            return None

        if self.check_exclusion(item):
            return None
        self.add_exclusion(item)

        f = getattr(self, f'process_{item.itype}', lambda self, _: None)
        return f(item)

    def reset(self):
        self.deque.clear()
        self.results.clear()
        self.gdb.clear()


class RobotScraper(Scraper):
    def process_domain(self, item: ScrapeItem):
        if not item.uri:
            return None
        self.enqueue(ScrapeItem('no_content', norm_url('/sitemap.xml', item.uri), stack=[item.uri, *item.stack]))
        self.enqueue(ScrapeItem('no_content', norm_url(item.uri), stack=[item.uri, *item.stack]))
        r = self.rm.get(norm_url('/robots.txt', item.uri))
        if r.status_code == 200:
            for l in r.text.splitlines():
                l = l.strip()
                if l.startswith('#'):
                    continue
                if l.startswith('Disallow'):
                    path = ':'.join(l.split(':')[1:]).strip()
                    if path and '*' not in path:
                        # Don't scrape wildcard paths
                        self.enqueue_front(ScrapeItem('content', norm_url(path, item.uri), stack=[item.uri, *item.stack]))
                    else:
                        x = self.results.get(item.uri, {})
                        res = x.get('robots', [])
                        res.append(path)
                        x['robots'] = res
                        self.results[item.uri] = x
            return {'item': item, 'req': [r], 'entries': {'results':[item.uri]}, 'stack': item.stack}
        return None

    def process_no_content(self, item: ScrapeItem):
        # TODO: allow disabling no_content for DNS(et al.)-based alternative
        # TODO: heuristics (maybe bayesian threshold?) on efficacy of recursive per-domain scraping
        uri = norm_url(item.uri)
        r = self.rm.get(uri)
        if r.status_code == 200:
            o = urlparse(uri)
            urls = extract_urls(r.text, o.netloc)
            exclusion_set = self.gdb.get(f'excluded_domain', set())
            for url in urls:
                u = urlparse(url)
                # Add new domains
                if re.match(domain_pattern, u.netloc) and u.netloc not in exclusion_set:
                    # Temporary exclusion until fully processed
                    exclusion_set.add(u.netloc)
                    self.enqueue_front(ScrapeItem('domain', u.netloc, stack=[item.uri, *item.stack]))

                # Add new non_content urls to discover more domains
                nitem = ScrapeItem('no_content', url, stack=[item.uri, *item.stack])
                if not self.check_exclusion(nitem):
                    self.enqueue(nitem)
            return {'item': item, 'req': [r], 'stack': item.stack}
        return None

    def process_content(self, item: ScrapeItem):
        u = urlparse(item.uri)
        domain = u.netloc
        r = self.rm.get(item.uri)
        if r.status_code < 400:
            # TODO: take screenshot?
            urls = extract_urls(r.text, domain)
            for url in urls:
                self.enqueue(ScrapeItem('no_content', url, {'subcontent',*(item.tags or set())}, stack=[item.uri, *item.stack]))

            with self.results.transact(True):
                key = f'req::{item.uri}'
                self.results[key] = r
                x = self.results.get(domain, {})
                z = x.get('content', set())
                # TODO: add option for imgs and others?
                z.add(key)
                x['content'] = z
                if item.tags:
                    z = x.get('tags', {})
                    z[key] = item.tags
                    self.results['tags'] = z
                self.results[domain] = x
            return {'item': item, 'req': [r], 'entries': {'results': [key, domain]},'stack': item.stack}
        elif r.status_code <= 403 or r.status_code >= 500:
            # No content but still a valid 'page'
            with self.results.transact(True):
                x = self.results.get(domain, {})
                z = x.get('bad_response', [])
                z.append({'uri': item.uri, 'status': r.status_code, 'text': r.text, 'tags': item.tags})
                x['bad_response'] = z
                self.results[domain] = x
            return {'item': item, 'req': [r], 'entries': {'results': [domain]}, 'stack': item.stack}
        else:
            # Page does not exist (or is not publically accessable w/ fake 404)
            with self.results.transact(True):
                x = self.results.get(domain, {})
                z = x.get('inaccessable', set())
                z.add(item.uri)
                x['inaccessable'] = z
                self.results[domain] = x
            return {'item': item, 'req': [r], 'entries': {'results': [domain]}, 'stack': item.stack}
            
