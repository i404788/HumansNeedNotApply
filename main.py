from scraper import RobotScraper, RequestManager, ScrapeItem
from diskcache import FanoutCache
import time

if __name__ == '__main__':
    db = FanoutCache('db')
    db.clear()
    r = RequestManager()
    s = RobotScraper(r)
    s.reset()

    s.enqueue(ScrapeItem('domain', 'git.devdroplets.com'))

    while s.has_next():
        result = s.next()
        if result:
            print('Got result:', result['item'])
            time.sleep(1)
