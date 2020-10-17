from scraper import RobotScraper, RequestManager, ScrapeItem
from diskcache import FanoutCache
import time

if __name__ == '__main__':
    db = FanoutCache('db')
    cache = db.cache('Scraper-results')

    for x in cache:
        print(x, cache[x])
