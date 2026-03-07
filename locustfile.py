# Run Locust using:
#
#locust -f locustfile.py
# Open the Locust web interface in your browser:
#     http://localhost:8089
#
# In the UI, enter the following settings:
# • Number of users: 10–50
# • Spawn rate: 2–5 users/second
# • Host: https://juice-shop.herokuapp.com
# • Run time: 3m
#
# Click “Start Swarming” to begin the load test.

from locust import User, task, between
from xss_security_gui.crawler import crawl_site


class CrawlerUser(User):
    # Random delay between task executions to simulate realistic user behavior
    wait_time = between(1, 3)

    @task
    def run_crawler(self):
        # Target website for crawling (OWASP Juice Shop is ideal for testing)
        url = "https://juice-shop.herokuapp.com/"

        result = crawl_site(
            url=url,
            depth=0,
            session=None,
            gui_callback=None,
            max_links=50,
            max_scripts=50,
            aggressive=True,
            parallel=True
        )

        # Basic result logging for debugging and performance observation
        if result.get("error"):
            print(f"[ERROR] {result['url']} → {result['error']}")
        else:
            print(f"[OK] Crawled: {result['url']}")