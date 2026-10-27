import unittest

from app.state import USERS, reset_state
from tests.client import Client


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_reflected_xss_vulnerable_vs_secure(self):
        payload = "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
        vulnerable = Client("vulnerable").request("/search?q=" + payload)
        secure = Client("secure").request("/search?q=" + payload)
        self.assertIn('<img src=x onerror=alert(1)>', vulnerable.body)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', secure.body)

    def test_stored_xss_vulnerable_vs_secure(self):
        payload = '<svg onload=alert(1)>'
        v = Client("vulnerable")
        s = Client("secure")
        v.request("/reviews", "POST", data={"body": payload})
        vulnerable = v.request("/reviews")
        reset_state()
        s.request("/reviews", "POST", data={"body": payload})
        secure = s.request("/reviews")
        self.assertIn(payload, vulnerable.body)
        self.assertIn('&lt;svg onload=alert(1)&gt;', secure.body)

    def test_role_cookie_tampering_only_works_in_vulnerable_mode(self):
        v = Client("vulnerable")
        v.cookies["role"] = "admin"
        vulnerable = v.request("/admin")
        s = Client("secure")
        s.cookies["role"] = "admin"
        secure = s.request("/admin")
        self.assertEqual(200, vulnerable.status_code)
        self.assertEqual(403, secure.status_code)

    def test_csrf_missing_token_is_rejected_in_secure_mode(self):
        v = Client("vulnerable")
        v.request("/login?user=member")
        vulnerable = v.request("/account/email", "POST", data={"email": "changed@example.test"})
        self.assertEqual(303, vulnerable.status_code)

        reset_state()
        s = Client("secure")
        s.request("/login?user=member")
        secure = s.request("/account/email", "POST", data={"email": "changed@example.test"})
        self.assertEqual(403, secure.status_code)
        self.assertEqual("member@example.test", USERS["member"]["email"])

    def test_negative_reward_redemption_increases_balance_only_in_vulnerable_mode(self):
        original = USERS["member"]["points"]
        v = Client("vulnerable")
        v.cookies["role"] = "admin"
        r = v.request(
            "/api/rewards/redeem",
            "POST",
            json_body={"username": "member", "amount": -original},
        )
        self.assertEqual(200, r.status_code)
        self.assertEqual(original * 2, USERS["member"]["points"])

        reset_state()
        s = Client("secure")
        s.request("/login?user=admin")
        r = s.request(
            "/api/rewards/redeem",
            "POST",
            json_body={"username": "member", "amount": -original},
        )
        self.assertEqual(400, r.status_code)
        self.assertEqual(original, USERS["member"]["points"])

    def test_cors_sensitive_api_is_hardened(self):
        v = Client("vulnerable")
        vulnerable = v.request("/api/admin/users", headers={"Origin": "https://evil.example"})
        self.assertIn("*", vulnerable.header_values("Access-Control-Allow-Origin"))

        s = Client("secure")
        secure = s.request("/api/admin/users", headers={"Origin": "https://evil.example"})
        self.assertEqual(403, secure.status_code)
        self.assertNotIn("*", secure.header_values("Access-Control-Allow-Origin"))


if __name__ == "__main__":
    unittest.main()
