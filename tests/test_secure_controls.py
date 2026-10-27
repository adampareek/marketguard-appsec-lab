import re
import unittest

from app.state import USERS, reset_state
from tests.client import Client


class SecureControlTests(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_secure_admin_session_works(self):
        c = Client("secure")
        login = c.request("/login?user=admin")
        self.assertEqual(200, login.status_code)
        self.assertIn("session", c.cookies)
        admin = c.request("/admin")
        self.assertEqual(200, admin.status_code)

    def test_secure_csrf_token_allows_account_change(self):
        c = Client("secure")
        c.request("/login?user=member")
        account = c.request("/account")
        match = re.search(r'name="csrf" value="([a-f0-9]+)"', account.body)
        self.assertIsNotNone(match)
        update = c.request(
            "/account/email",
            "POST",
            data={"email": "new@example.test", "csrf": match.group(1)},
        )
        self.assertEqual(303, update.status_code)
        self.assertEqual("new@example.test", USERS["member"]["email"])

    def test_secure_positive_reward_redemption(self):
        c = Client("secure")
        c.request("/login?user=admin")
        before = USERS["member"]["points"]
        response = c.request(
            "/api/rewards/redeem",
            "POST",
            json_body={"username": "member", "amount": 20},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual(before - 20, USERS["member"]["points"])


if __name__ == "__main__":
    unittest.main()
