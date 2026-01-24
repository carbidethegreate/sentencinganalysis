import unittest

from pacer_logging import redact_payload, scrub_log_message


class PacerLoggingTests(unittest.TestCase):
    def test_scrub_log_message_redacts_sensitive_fields(self):
        message = (
            'payload={"nextGenCSO":"token-123","password":"secret","otpCode":"654321"}'
        )
        scrubbed = scrub_log_message(message)
        self.assertNotIn("token-123", scrubbed)
        self.assertNotIn("secret", scrubbed)
        self.assertNotIn("654321", scrubbed)

    def test_redact_payload_hides_sensitive_keys(self):
        payload = {
            "nextGenCSO": "token-123",
            "password": "secret",
            "otpCode": "654321",
            "clientCode": "ABC",
            "loginId": "user",
            "username": "user@example.com",
            "safe": "ok",
        }
        redacted = redact_payload(payload)
        self.assertEqual(redacted["nextGenCSO"], "<redacted>")
        self.assertEqual(redacted["password"], "<redacted>")
        self.assertEqual(redacted["otpCode"], "<redacted>")
        self.assertEqual(redacted["clientCode"], "<redacted>")
        self.assertEqual(redacted["loginId"], "<redacted>")
        self.assertEqual(redacted["username"], "<redacted>")
        self.assertEqual(redacted["safe"], "ok")


if __name__ == "__main__":
    unittest.main()
