import time
import random
import requests


class HttpClient:
    def __init__(self, timeout=12, retries=3):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        self.timeout = timeout
        self.retries = retries

    def get(self, url: str):
        last_exc = None
        for i in range(self.retries):
            try:
                return self.session.get(url, timeout=self.timeout)
            except requests.RequestException as e:
                last_exc = e
                time.sleep((2 ** i) + random.random())
        raise last_exc
