from cloudscraper import create_scraper
from diskcache import FanoutCache
from bs4 import BeautifulSoup
from typing import NamedTuple
# TODO: get seed from somewhere

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
        r = self.scraper.get(url, *args, **kwargs);
        self.db['scraper'] = self.scraper
        return r

class ScrapeItem(NamedTuple):
    itype: str
    uri: str

def norm_url(self, path_or_url: str, domain: str=''):
    if path_or_url[0] == '/':
        # Assume relative url
        return f'http://{domain}/{path_or_url}'
    elif '://' in path_or_url:
        # Assume scheme and domain already filled in
        return path_or_url
    else:
        # Missing scheme
        return f'http://{path_or_url}'

class Scraper:
    def __init__(self, req_manager, seeds=[], db_path='db'):
        self.rm = req_manager
        self.seeds = seeds
        self.gdb = FanoutCache(db_path)

        # Future pages to scrape (FIFO)
        self.deque = self.gdb.deque('Scraper-deque')
        self.results = self.gdb.cache('Scraper-results')
        
        # After pages are finished, domains is excluded
        self.excluded_domains = self.gdb.get('excluded_domains', set())
        self.excluded_pages = self.gdb.get('excluded_pages', set())

    def enqueue(self, item: ScrapeItem):
        self.deque.append(item)

    def process_robot(self, text, domain):
        for l in r.text.splitlines():
            if l.startswith('Disallow'):
                path = l.split(':')[-1].trim()
                if '*' not in path:
                    # Don't scrape wildcard paths
                    self.enqueue(ScrapeItem('content', norm_url(path, domain)))
                else:
                    x = self.results.get(domain, {})
                    res = x.get('robots', [])
                    res.append({'wildcard': l})
                    x['robots'] = res
                    self.results[domain] = x
    
    def check_exclusion(item: ScrapeItem):        
        exclusion_set = self.gdb.get(f'excluded_{item.itype}', set())
        return exclusion_set.has(item.uri)

    def add_exclusion(item: ScrapeItem):
        exclusion_set = self.gdb.get(f'excluded_{item.itype}', set())
        exclusion_set.add(item.uri)
        self.gdb[f'excluded_{item.itype}'] = exclusion_set

    def next(self):
        item = self.deque.popleft()
        if self.check_exclusion(item):
            return None
        self.add_exclusion(item)

        # TODO: heuristics on efficacy of recursive per-domain scraping
        if item.itype == 'domain':
            self.enqueue(ScrapeItem('no_content', norm_url('/sitemap.xml', item.uri)))
            self.enqueue(ScrapeItem('no_content', norm_url(item.uri)))
            r = self.rm.get(norm_url('/robot.txt', item.uri))
            if r.status_code == 200:
                self.process_robot(r.text, item.uri)
        elif item.itype == 'no_content':
            item
            # TODO: if relative link normalize to domain
            # TODO: extract urls that are not in excluded_pages
        elif item.itype == 'content':
            # TODO: put in self.results
            # TODO: check if accessable (not 404)
            # TODO: if so take snapshot and save url
            # TODO: scrape sub-urls

        pass

