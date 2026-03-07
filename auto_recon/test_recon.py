# xss_security_gui/auto_recon/test_recon.py
import unittest
from xss_security_gui.auto_recon.planner import AttackPlanner
from xss_security_gui.auto_recon.payloads import PayloadGenerator
from xss_security_gui.auto_recon.analyzer import ThreatConnector
from xss_security_gui.auto_recon.scanner import EndpointScanner


class TestAutoRecon(unittest.TestCase):
    def test_payload_generation(self):
        EndpointScanner("https://jsonplaceholder.typicode.com")
        endpoints = [
            {"method": "GET", "url": "/posts"},
            {"method": "GET", "url": "/comments"},
            {"method": "GET", "url": "/albums"},
            {"method": "GET", "url": "/photos"},
            {"method": "GET", "url": "/todos"},
            {"method": "GET", "url": "/users"},
        ]
        generator = PayloadGenerator(endpoints)
        payloads = generator.generate()
        self.assertTrue(len(payloads) > 0)

    def test_attack_execution(self):
        fake_payload = [{"method": "GET", "url": "https://jsonplaceholder.typicode.com/posts/1/comments"}]
        planner = AttackPlanner(fake_payload)
        responses = planner.execute()
        self.assertEqual(responses[0]['status'], 200)
print(ThreatConnector)

if __name__ == "__main__":
    unittest.main()