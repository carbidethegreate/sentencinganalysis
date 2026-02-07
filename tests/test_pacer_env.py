import unittest

from pacer_env import validate_pacer_environment_config


class PacerEnvValidationTests(unittest.TestCase):
    def test_validate_accepts_matching_qa_hosts(self):
        config = validate_pacer_environment_config(
            "https://qa-login.uscourts.gov",
            "https://qa-pcl.uscourts.gov/pcl-public-api/rest",
        )
        self.assertEqual(config.auth_env, "qa")
        self.assertEqual(config.pcl_env, "qa")

    def test_validate_accepts_matching_prod_hosts(self):
        config = validate_pacer_environment_config(
            "https://pacer.login.uscourts.gov",
            "https://pcl.uscourts.gov/pcl-public-api/rest",
        )
        self.assertEqual(config.auth_env, "prod")
        self.assertEqual(config.pcl_env, "prod")

    def test_validate_accepts_hosts_with_ports(self):
        config = validate_pacer_environment_config(
            "https://qa-login.uscourts.gov:443",
            "https://qa-pcl.uscourts.gov:443/pcl-public-api/rest",
        )
        self.assertEqual(config.auth_env, "qa")
        self.assertEqual(config.pcl_env, "qa")

    def test_validate_rejects_qa_pcl_with_prod_auth(self):
        with self.assertRaises(ValueError) as ctx:
            validate_pacer_environment_config(
                "https://pacer.login.uscourts.gov",
                "https://qa-pcl.uscourts.gov/pcl-public-api/rest",
            )
        self.assertIn("PACER_AUTH_BASE_URL=https://qa-login.uscourts.gov", str(ctx.exception))

    def test_validate_rejects_prod_pcl_with_qa_auth(self):
        with self.assertRaises(ValueError) as ctx:
            validate_pacer_environment_config(
                "https://qa-login.uscourts.gov",
                "https://pcl.uscourts.gov/pcl-public-api/rest",
            )
        self.assertIn("PACER_AUTH_BASE_URL=https://pacer.login.uscourts.gov", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
