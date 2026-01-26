#!/usr/bin/env python3
"""
Unit tests for redaudit.core.wizard module.
"""

import unittest
import os
from unittest.mock import MagicMock, patch
from redaudit.core.wizard import Wizard
from redaudit.utils.constants import COLORS


class MockAuditor(Wizard):
    def __init__(self):
        self.config = {}
        self.ui = MagicMock()
        self.ui.colors = COLORS

        def t_side_effect(key, *args):
            if key in ("auth_cred_number", "auth_creds_summary"):
                return f"{key} %s"
            if key == "auth_loaded_creds":
                return f"{key} {{}}"
            return f"{key}"

        self.ui.t.side_effect = t_side_effect
        self.ui.print_status = MagicMock()
        self.lang = "en"
        self.rate_limit_delay = 0.0
        self.signal_handler = MagicMock()


class TestWizard(unittest.TestCase):
    def setUp(self):
        self.wizard = MockAuditor()

    def test_clear_screen_dry_run(self):
        self.wizard.config["dry_run"] = True
        with patch("os.system") as mock_system:
            self.wizard.clear_screen()
            mock_system.assert_not_called()

    def test_clear_screen_real(self):
        self.wizard.config["dry_run"] = False
        with patch("os.system") as mock_system, patch("os.name", "posix"):
            self.wizard.clear_screen()
            mock_system.assert_called_with("clear")

    def test_print_banner(self):
        with patch("builtins.print") as mock_print:
            self.wizard.print_banner()
            mock_print.assert_called()

    @patch("redaudit.core.wizard.Wizard._read_key")
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=True)
    def test_arrow_menu(self, mock_use_arrow, mock_read_key):
        # Simulate 'down', 'down', 'enter'
        mock_read_key.side_effect = ["down", "down", "enter"]

        options = ["Opt 1", "Opt 2", "Opt 3"]
        result = self.wizard._arrow_menu("Choose", options, default=0)
        self.assertEqual(result, 2)  # 0 -> 1 -> 2

    @patch("builtins.input", side_effect=["0"])
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=False)
    def test_show_main_menu_text(self, mock_use_arrow, mock_input):
        # Text mode
        choice = self.wizard.show_main_menu()
        self.assertEqual(choice, 0)

    @patch("redaudit.core.wizard.Wizard._arrow_menu", return_value=4)  # Exit
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=True)
    def test_show_main_menu_arrow(self, mock_use_arrow, mock_arrow_menu):
        choice = self.wizard.show_main_menu()
        self.assertEqual(choice, 0)

    @patch("builtins.input", side_effect=["yes"])
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=False)
    def test_ask_yes_no_text(self, mock_use_arrow, mock_input):
        self.assertTrue(self.wizard.ask_yes_no("Proceed?"))

    @patch("redaudit.core.wizard.Wizard._arrow_menu", return_value=0)  # Yes
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=True)
    def test_ask_yes_no_arrow(self, mock_use_arrow, mock_arrow_menu):
        self.assertTrue(self.wizard.ask_yes_no("Proceed?"))

    @patch("builtins.input", side_effect=["50"])
    def test_ask_number(self, mock_input):
        val = self.wizard.ask_number("Threads?", default=10, min_val=1, max_val=100)
        self.assertEqual(val, 50)

    @patch("builtins.input", side_effect=["invalid", "50"])
    def test_ask_number_retry(self, mock_input):
        val = self.wizard.ask_number("Threads?", default=10)
        self.assertEqual(val, 50)

    @patch("builtins.input", side_effect=[""])
    def test_ask_number_default(self, mock_input):
        val = self.wizard.ask_number("Threads?", default=10)
        self.assertEqual(val, 10)

    @patch("builtins.input", side_effect=["all"])
    def test_ask_number_all(self, mock_input):
        val = self.wizard.ask_number("Hosts?", default=10)
        self.assertEqual(val, "all")

    @patch("builtins.input", side_effect=["10.0.0.1, 10.0.0.2"])
    def test_ask_manual_network(self, mock_input):
        res = self.wizard.ask_manual_network()
        # parse_target_tokens normalizes single IPs to /32
        self.assertIn("10.0.0.1/32", res)
        self.assertIn("10.0.0.2/32", res)

    @patch("builtins.input", side_effect=["https://hooks.slack.com/services/XXX"])
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)  # Yes hooks
    def test_ask_webhook_url(self, mock_yes_no, mock_input):
        # We also need to answer NO to "Test webhook?" or mock it
        # The sequence of ask_yes_no:
        # 1. Enable webhook? -> Mock returns True
        # 2. Test webhook? -> Mock returns True (if I want to test that path)
        # But ask_yes_no mock here applies to ALL calls.
        # If I want different answers, I use side_effect.
        mock_yes_no.side_effect = [True, False]
        url = self.wizard.ask_webhook_url()
        self.assertEqual(url, "https://hooks.slack.com/services/XXX")

    def test_apply_run_defaults(self):
        defaults = {
            "scan_mode": "rapido",
            "threads": 50,
            "rate_limit": 2.5,
            "scan_vulnerabilities": False,
            "output_dir": "/tmp/test",
            "udp_mode": "top-100",
            "topology_enabled": True,
        }
        self.wizard._apply_run_defaults(defaults)

        self.assertEqual(self.wizard.config["scan_mode"], "rapido")
        self.assertEqual(self.wizard.config["threads"], 50)
        self.assertEqual(self.wizard.rate_limit_delay, 2.5)
        self.assertFalse(self.wizard.config["scan_vulnerabilities"])
        self.assertEqual(self.wizard.config["output_dir"], "/tmp/test")
        self.assertTrue(self.wizard.config["topology_enabled"])

    def test_is_cancel_input(self):
        self.assertTrue(self.wizard._is_cancel_input("cancel"))
        self.assertTrue(self.wizard._is_cancel_input("c"))
        self.assertFalse(self.wizard._is_cancel_input("no"))
        self.assertFalse(self.wizard._is_cancel_input(""))
        self.assertFalse(self.wizard._is_cancel_input(None))

    @patch("builtins.input", side_effect=["", "bad", "10.0.0.0/24"])
    def test_ask_manual_network_invalid_then_valid(self, mock_input):
        with patch(
            "redaudit.core.wizard.parse_target_tokens",
            side_effect=[([], ["bad"]), (["10.0.0.0/24"], [])],
        ):
            res = self.wizard.ask_manual_network()
        self.assertEqual(res, ["10.0.0.0/24"])

    @patch("builtins.input", side_effect=["10.0.0.0/24", "10.0.0.0/24"])
    def test_ask_manual_network_empty_parse_then_valid(self, mock_input):
        with patch(
            "redaudit.core.wizard.parse_target_tokens",
            side_effect=[([], []), (["10.0.0.0/24"], [])],
        ):
            res = self.wizard.ask_manual_network()
        self.assertEqual(res, ["10.0.0.0/24"])

    def test_load_keyring_from_invoking_user_none(self):
        self.assertIsNone(self.wizard._load_keyring_from_invoking_user(""))
        self.assertIsNone(self.wizard._load_keyring_from_invoking_user(None))

    def test_load_keyring_from_invoking_user_env_error(self):
        dummy = type("Dummy", (), {"pw_uid": 1000})
        with (
            patch("redaudit.core.wizard.shutil.which", return_value="/usr/bin/sudo"),
            patch("pwd.getpwnam", return_value=dummy),
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run", return_value=type("R", (), {"returncode": 1, "stdout": ""})()),
        ):
            self.assertIsNone(self.wizard._load_keyring_from_invoking_user("alice"))

    def test_load_keyring_from_invoking_user_pwd_error(self):
        with (
            patch("redaudit.core.wizard.shutil.which", return_value="/usr/bin/sudo"),
            patch("pwd.getpwnam", side_effect=Exception("boom")),
            patch("subprocess.run", return_value=type("R", (), {"returncode": 1, "stdout": ""})()),
        ):
            self.assertIsNone(self.wizard._load_keyring_from_invoking_user("alice"))

    def test_load_keyring_from_invoking_user_empty_payload(self):
        dummy = type("Dummy", (), {"pw_uid": 1000})
        with (
            patch("redaudit.core.wizard.shutil.which", return_value="/usr/bin/sudo"),
            patch("pwd.getpwnam", return_value=dummy),
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run", return_value=type("R", (), {"returncode": 0, "stdout": ""})()),
        ):
            self.assertIsNone(self.wizard._load_keyring_from_invoking_user("alice"))

    def test_load_keyring_from_invoking_user_non_dict_payload(self):
        dummy = type("Dummy", (), {"pw_uid": 1000})
        with (
            patch("redaudit.core.wizard.shutil.which", return_value="/usr/bin/sudo"),
            patch("pwd.getpwnam", return_value=dummy),
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
            patch(
                "subprocess.run",
                return_value=type("R", (), {"returncode": 0, "stdout": "[]"})(),
            ),
        ):
            self.assertIsNone(self.wizard._load_keyring_from_invoking_user("alice"))

    def test_apply_keyring_credentials_skips_non_dict(self):
        auth_config = {}
        loaded = self.wizard._apply_keyring_credentials(
            auth_config,
            ["bad", {"protocol": "SSH", "username": "u", "password": "p"}],
        )
        self.assertEqual(loaded, 1)
        self.assertEqual(auth_config["auth_ssh_user"], "u")

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    def test_check_and_load_saved_credentials_invoking_user(self, mock_yes_no):
        payload = {"summary": [("SSH", "u")], "creds": [{"protocol": "SSH", "username": "u"}]}
        with (
            patch(
                "redaudit.core.credentials.KeyringCredentialProvider.get_saved_credential_summary",
                return_value=[],
            ),
            patch("redaudit.core.wizard.get_invoking_user", return_value="alice"),
            patch(
                "redaudit.core.wizard.Wizard._load_keyring_from_invoking_user", return_value=payload
            ),
            patch("redaudit.core.wizard.Wizard._apply_keyring_credentials", return_value=1),
        ):
            auth_config = {"auth_enabled": True}
            self.assertTrue(self.wizard._check_and_load_saved_credentials(auth_config))

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    def test_check_and_load_saved_credentials_snmp(self, mock_yes_no):
        cred = type(
            "Cred",
            (),
            {
                "username": "snmp",
                "snmp_auth_proto": "SHA",
                "snmp_auth_pass": "auth",
                "snmp_priv_proto": "AES",
                "snmp_priv_pass": "priv",
                "domain": None,
                "password": None,
                "private_key": None,
                "private_key_passphrase": None,
            },
        )()
        with (
            patch(
                "redaudit.core.credentials.KeyringCredentialProvider.get_saved_credential_summary",
                return_value=[("SNMP", "snmp")],
            ),
            patch(
                "redaudit.core.credentials.KeyringCredentialProvider.get_credential",
                return_value=cred,
            ),
        ):
            auth_config = {"auth_enabled": True}
            self.assertTrue(self.wizard._check_and_load_saved_credentials(auth_config))
            self.assertEqual(auth_config["auth_snmp_user"], "snmp")

    def test_check_and_load_saved_credentials_exception(self):
        with patch(
            "redaudit.core.credentials.KeyringCredentialProvider",
            side_effect=Exception("boom"),
        ):
            auth_config = {"auth_enabled": True}
            self.assertFalse(self.wizard._check_and_load_saved_credentials(auth_config))

    @patch("builtins.input", side_effect=["cancel"])
    def test_collect_universal_credentials_cancel(self, mock_input):
        self.assertIsNone(self.wizard._collect_universal_credentials())

    @patch("builtins.input", side_effect=[""])
    def test_collect_universal_credentials_empty_user(self, mock_input):
        creds = self.wizard._collect_universal_credentials()
        self.assertEqual(creds, [])

    @patch("builtins.input", side_effect=["user"])
    @patch("getpass.getpass", side_effect=Exception("boom"))
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=False)
    def test_collect_universal_credentials_getpass_exception(self, mock_yes, mock_pass, mock_input):
        creds = self.wizard._collect_universal_credentials()
        self.assertEqual(creds[0]["pass"], "")

    @patch("builtins.input", side_effect=["cancel"])
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    def test_collect_advanced_credentials_ssh_cancel(self, mock_yes, mock_input):
        auth_config = {"auth_enabled": True}
        self.assertTrue(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["root"])
    @patch("getpass.getpass", side_effect=Exception("boom"))
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, False, False])
    @patch("redaudit.core.wizard.Wizard.ask_choice", return_value=1)
    def test_collect_advanced_credentials_ssh_pass_exception(
        self, mock_choice, mock_yes, mock_pass, mock_input
    ):
        auth_config = {"auth_enabled": True}
        self.assertFalse(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["root"])
    @patch("getpass.getpass", return_value="pw")
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, False, False])
    @patch("redaudit.core.wizard.Wizard.ask_choice", return_value=1)
    def test_collect_advanced_credentials_ssh_password(
        self, mock_choice, mock_yes, mock_pass, mock_input
    ):
        auth_config = {"auth_enabled": True}
        self.assertFalse(self.wizard._collect_advanced_credentials(auth_config))
        self.assertEqual(auth_config["auth_ssh_pass"], "pw")

    @patch("builtins.input", side_effect=["cancel"])
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[False, True])
    def test_collect_advanced_credentials_smb_cancel(self, mock_yes, mock_input):
        auth_config = {"auth_enabled": True}
        self.assertTrue(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["Admin", ""])
    @patch("getpass.getpass", side_effect=Exception("boom"))
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[False, True, False])
    def test_collect_advanced_credentials_smb_pass_exception(self, mock_yes, mock_pass, mock_input):
        auth_config = {"auth_enabled": True}
        self.assertFalse(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["cancel"])
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[False, False, True])
    def test_collect_advanced_credentials_snmp_cancel(self, mock_yes, mock_input):
        auth_config = {"auth_enabled": True}
        self.assertTrue(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["snmp"])
    @patch("getpass.getpass", side_effect=[Exception("auth"), Exception("priv")])
    @patch("redaudit.core.wizard.Wizard.ask_choice", side_effect=[0, 0])
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[False, False, True])
    def test_collect_advanced_credentials_snmp_pass_exceptions(
        self, mock_yes, mock_choice, mock_pass, mock_input
    ):
        auth_config = {"auth_enabled": True}
        self.assertFalse(self.wizard._collect_advanced_credentials(auth_config))

    @patch("builtins.input", side_effect=["back"])
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=False)
    def test_ask_choice_with_back_text_cancel(self, mock_use_arrow, mock_input):
        res = self.wizard.ask_choice_with_back("Q", ["A", "B"], step_num=2)
        self.assertEqual(res, self.wizard.WIZARD_BACK)

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=False)
    def test_ask_auth_config_no(self, mock_ask):
        res = self.wizard.ask_auth_config(skip_intro=False)
        self.assertFalse(res["auth_enabled"])

    @patch("redaudit.core.wizard.Wizard._check_and_load_saved_credentials", return_value=True)
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[False])  # "Add more?" -> No
    def test_ask_auth_config_keyring(self, mock_ask, mock_keyring):
        res = self.wizard.ask_auth_config(skip_intro=True)
        self.assertTrue(res["auth_enabled"])

    @patch("redaudit.core.wizard.Wizard._check_and_load_saved_credentials", return_value=False)
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)  # Intro yes
    @patch("redaudit.core.wizard.Wizard.ask_choice_with_back", return_value=-1)  # Back
    def test_ask_auth_config_back(self, mock_choice, mock_ask, mock_keyring):
        res = self.wizard.ask_auth_config()
        self.assertFalse(res["auth_enabled"])

    @patch("redaudit.core.wizard.Wizard._check_and_load_saved_credentials", return_value=False)
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    @patch("redaudit.core.wizard.Wizard.ask_choice_with_back", return_value=0)  # Universal
    @patch(
        "redaudit.core.wizard.Wizard._collect_universal_credentials",
        return_value=[{"user": "u", "pass": "p"}],
    )
    def test_ask_auth_config_universal(self, mock_coll, mock_choice, mock_ask, mock_keyring):
        res = self.wizard.ask_auth_config()
        self.assertTrue(res["auth_enabled"])
        self.assertEqual(res["auth_credentials"], [{"user": "u", "pass": "p"}])

    @patch("redaudit.core.wizard.Wizard._check_and_load_saved_credentials", return_value=True)
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, True])
    @patch("redaudit.core.wizard.Wizard.ask_choice_with_back", return_value=1)  # Advanced
    @patch("redaudit.core.wizard.Wizard._collect_advanced_credentials", return_value=True)
    def test_ask_auth_config_keyring_advanced_cancel(
        self, mock_coll, mock_choice, mock_ask, mock_keyring
    ):
        res = self.wizard.ask_auth_config()
        self.assertTrue(res["auth_enabled"])

    @patch("builtins.input", side_effect=["u1", "u2"])
    @patch("getpass.getpass", side_effect=["p1", "p2"])
    @patch(
        "redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, False]
    )  # Add another? Yes, then No
    def test_collect_universal_credentials(self, mock_ask, mock_pass, mock_input):
        creds = self.wizard._collect_universal_credentials()  # type: ignore
        self.assertEqual(len(creds), 2)
        self.assertEqual(creds[0]["user"], "u1")
        self.assertEqual(creds[0]["pass"], "p1")

    @patch("redaudit.core.wizard.Wizard._check_and_load_saved_credentials", return_value=False)
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    @patch("redaudit.core.wizard.Wizard.ask_choice_with_back", return_value=1)  # Advanced
    @patch("redaudit.core.wizard.Wizard._collect_advanced_credentials", return_value=False)
    def test_ask_auth_config_advanced(self, mock_coll, mock_choice, mock_ask, mock_keyring):
        res = self.wizard.ask_auth_config()
        self.assertTrue(res["auth_enabled"])

    @patch(
        "builtins.input", side_effect=["root", "~/.ssh/id_rsa", "admin", "WORKGROUP", "snmpuser"]
    )
    @patch("getpass.getpass", side_effect=["pass", "authkey", "privkey"])
    @patch(
        "redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, True, True]
    )  # SSH yes, SMB yes, SNMP yes
    @patch(
        "redaudit.core.wizard.Wizard.ask_choice", side_effect=[0, 0, 0]
    )  # SSH key, SNMP auth SHA, SNMP priv AES
    def test_collect_advanced_credentials(self, mock_choice, mock_ask, mock_pass, mock_input):
        config = {}
        self.wizard._collect_advanced_credentials(config)  # type: ignore
        self.assertEqual(config["auth_ssh_user"], "root")
        self.assertEqual(config["auth_smb_user"], "admin")
        self.assertEqual(config["auth_snmp_user"], "snmpuser")

    @patch("shutil.which", return_value="/usr/bin/sudo")
    @patch("subprocess.run")
    def test_load_keyring_invoking_user(self, mock_run, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = (
            '{"summary": [["SSH", "u1"]], "creds": [{"protocol": "SSH", "username": "u1"}]}'
        )
        mock_run.return_value = mock_res

        with patch("pwd.getpwnam", create=True) as mock_pwm:
            mock_pwm.return_value.pw_uid = 1000
            pl = self.wizard._load_keyring_from_invoking_user("user")
            self.assertIsNotNone(pl)
            self.assertEqual(pl["summary"][0][1], "u1")

    @patch("shutil.which", return_value="/usr/bin/sudo")
    @patch("subprocess.run")
    def test_load_keyring_invoking_user_env_vars(self, mock_run, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = '{"summary": [["SSH", "u1"]], "creds": []}'
        mock_run.return_value = mock_res

        dummy = type("Dummy", (), {"pw_uid": 1000})
        with (
            patch("pwd.getpwnam", return_value=dummy),
            patch("os.path.isdir", return_value=True),
            patch("os.path.exists", return_value=True),
        ):
            payload = self.wizard._load_keyring_from_invoking_user("user")
        self.assertIsNotNone(payload)
        cmd = mock_run.call_args[0][0]
        self.assertTrue(any("XDG_RUNTIME_DIR=" in item for item in cmd))
        self.assertTrue(any("DBUS_SESSION_BUS_ADDRESS=" in item for item in cmd))

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    def test_check_and_load_saved_credentials(self, mock_ask):
        with patch("redaudit.core.credentials.KeyringCredentialProvider") as mock_kv:
            mock_inst = mock_kv.return_value
            mock_inst.get_saved_credential_summary.return_value = [("SSH", "user", 0)]

            cred = MagicMock()
            cred.username = "user"
            cred.password = "pass"
            cred.private_key = None
            cred.private_key_passphrase = None
            mock_inst.get_credential.return_value = cred

            config = {}
            with patch("redaudit.core.wizard.get_invoking_user", return_value=None):
                res = self.wizard._check_and_load_saved_credentials(config)
                self.assertTrue(res)
                self.assertEqual(config["auth_ssh_user"], "user")

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=False)
    def test_check_and_load_saved_credentials_declined(self, mock_ask):
        payload = {"summary": [["SSH", "u1"]], "creds": []}
        with (
            patch(
                "redaudit.core.credentials.KeyringCredentialProvider.get_saved_credential_summary",
                return_value=[],
            ),
            patch("redaudit.core.wizard.get_invoking_user", return_value="user"),
            patch(
                "redaudit.core.wizard.Wizard._load_keyring_from_invoking_user",
                return_value=payload,
            ),
        ):
            auth_config = {"auth_enabled": True}
            self.assertFalse(self.wizard._check_and_load_saved_credentials(auth_config))

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)
    def test_check_and_load_saved_credentials_no_loaded(self, mock_ask):
        with patch("redaudit.core.credentials.KeyringCredentialProvider") as mock_kv:
            mock_inst = mock_kv.return_value
            mock_inst.get_saved_credential_summary.return_value = [("SSH", "user", 0)]
            mock_inst.get_credential.return_value = None
            auth_config = {"auth_enabled": True}
            self.assertFalse(self.wizard._check_and_load_saved_credentials(auth_config))

    @patch("builtins.input", side_effect=["private", "corp.local", "100"])  # SNMP, DNS, MaxTargets
    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=True)  # Yes to advanced
    def test_ask_net_discovery_options(self, mock_ask, mock_input):
        opts = self.wizard.ask_net_discovery_options()
        self.assertEqual(opts["snmp_community"], "private")
        self.assertEqual(opts["dns_zone"], "corp.local")
        self.assertEqual(opts["redteam_max_targets"], 100)

    @patch("redaudit.core.wizard.Wizard.ask_yes_no", return_value=False)
    def test_ask_net_discovery_options_no(self, mock_ask):
        opts = self.wizard.ask_net_discovery_options()
        self.assertEqual(opts["snmp_community"], "public")

    def test_show_defaults_summary(self):
        defaults = {
            "target_networks": ["10.0.0.0/24"],
            "scan_mode": "normal",
            "threads": 10,
            "output_dir": "/tmp",
            "rate_limit": 0.0,
            "udp_mode": "top-100",
            "udp_top_ports": 100,
            "topology_enabled": True,
            "scan_vulnerabilities": True,
            "cve_lookup_enabled": False,
            "generate_txt": True,
            "generate_html": True,
        }
        self.wizard._show_defaults_summary(defaults)
        self.wizard.ui.print_status.assert_called()

    def test_apply_keyring_credentials(self):
        config = {}
        creds = [
            {
                "protocol": "SSH",
                "username": "u1",
                "password": "p1",
                "private_key": "k1",
                "private_key_passphrase": "kp1",
            },
            {"protocol": "SMB", "username": "u2", "password": "p2", "domain": "d2"},
            {
                "protocol": "SNMP",
                "username": "u3",
                "snmp_auth_proto": "MD5",
                "snmp_auth_pass": "ap3",
                "snmp_priv_proto": "DES",
                "snmp_priv_pass": "pp3",
            },
        ]
        count = self.wizard._apply_keyring_credentials(config, creds)
        self.assertEqual(count, 3)
        self.assertEqual(config["auth_ssh_user"], "u1")
        self.assertEqual(config["auth_smb_user"], "u2")
        self.assertEqual(config["auth_snmp_user"], "u3")

    def test_test_webhook_success(self):
        mock_module = MagicMock()
        mock_module.send_webhook.return_value = True
        with patch.dict("sys.modules", {"redaudit.utils.webhook": mock_module}):
            res = self.wizard._test_webhook("https://url")
            self.assertTrue(res)

    def test_test_webhook_fail(self):
        mock_module = MagicMock()
        mock_module.send_webhook.return_value = False
        with patch.dict("sys.modules", {"redaudit.utils.webhook": mock_module}):
            res = self.wizard._test_webhook("https://url")
            self.assertFalse(res)

    def test_test_webhook_exception(self):
        mock_module = MagicMock()
        mock_module.send_webhook.side_effect = Exception("Error")
        with patch.dict("sys.modules", {"redaudit.utils.webhook": mock_module}):
            res = self.wizard._test_webhook("https://url")
            self.assertFalse(res)

    @patch("builtins.input", side_effect=["invalid", "1"])  # 1-based index in text mode
    def test_ask_choice_retry(self, mock_input):
        opts = ["Opt1", "Opt2"]
        # Force text mode on the instance
        with patch.object(self.wizard, "_use_arrow_menu", return_value=False):
            res = self.wizard.ask_choice("Q", opts, default=0)
            self.assertEqual(res, 0)

    @patch("shutil.which", return_value="/usr/bin/sudo")
    @patch("subprocess.run")
    def test_load_keyring_malformed_json(self, mock_run, mock_which):
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "NOT JSON"
        mock_run.return_value = mock_res

        with patch("pwd.getpwnam", create=True) as mock_pwm:
            mock_pwm.return_value.pw_uid = 1000
            pl = self.wizard._load_keyring_from_invoking_user("user")
            self.assertIsNone(pl)

    @patch("shutil.which", return_value=None)
    def test_load_keyring_no_sudo(self, mock_which):
        pl = self.wizard._load_keyring_from_invoking_user("user")
        self.assertIsNone(pl)

    def test_truncate_menu_text(self):
        text = f"{COLORS['FAIL']}Hello World{COLORS['ENDC']}"
        truncated = self.wizard._truncate_menu_text(text, 5)
        self.assertIn("He...", truncated)
        self.assertIn(COLORS["FAIL"], truncated)
        self.assertIn(COLORS["ENDC"], truncated)

    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch("tty.setraw")
    @patch("sys.stdin.read", side_effect=["a"])
    @patch("sys.stdin.fileno", return_value=0)
    @patch("os.name", "posix")
    def test_read_key_posix(self, mock_read, mock_fileno, mock_setraw, mock_setattr, mock_getattr):
        with patch.dict("sys.modules", {"termios": MagicMock(), "tty": MagicMock()}):
            key = self.wizard._read_key()
            self.assertEqual(key, "a")

    @patch("termios.tcgetattr")
    @patch("termios.tcsetattr")
    @patch("tty.setraw")
    @patch("sys.stdin.read", side_effect=["\x1b", "[A"])  # Up arrow (ESC, [A)
    @patch("sys.stdin.fileno", return_value=0)
    @patch("os.name", "posix")
    def test_read_key_arrow(self, mock_read, mock_fileno, mock_setraw, mock_setattr, mock_getattr):
        with patch.dict("sys.modules", {"termios": MagicMock(), "tty": MagicMock()}):
            key = self.wizard._read_key()
            self.assertEqual(key, "up")

    @patch(
        "redaudit.core.wizard.Wizard.ask_yes_no", side_effect=[True, False, False]
    )  # SSH Yes, SMB No, SNMP No
    @patch("builtins.input", side_effect=["u", "u", "u"])
    @patch("redaudit.core.wizard.Wizard.ask_choice", side_effect=[1, 1, 1, 1])  # Pass
    @patch("getpass.getpass", side_effect=Exception("Error"))
    def test_collect_advanced_credentials_exception(
        self, mock_getpass, mock_ask_choice, mock_input, mock_ask_yes_no
    ):
        config = {}
        self.wizard._collect_advanced_credentials(config)  # type: ignore
        self.assertIsNone(config.get("auth_ssh_pass"))

    def test_detect_os_banner_label(self):
        # mock_open read_data should produce lines when iterated
        data = 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04"'
        with patch("builtins.open", new_callable=unittest.mock.mock_open, read_data=data):
            with patch("os.path.exists", return_value=True):
                label = self.wizard._detect_os_banner_label()
                self.assertEqual(label, "UBUNTU")

    @patch("platform.system", return_value="Darwin")
    def test_detect_os_banner_macos(self, mock_sys):
        with patch("os.path.exists", return_value=False):
            label = self.wizard._detect_os_banner_label()
            self.assertEqual(label, "MACOS")

    @patch("redaudit.core.wizard.Wizard._read_key")
    @patch("redaudit.core.wizard.Wizard._use_arrow_menu", return_value=True)
    def test_arrow_menu_scroll(self, mock_use_arrow, mock_read_key):
        # 100 options. Scroll down.
        opts = [f"Opt{i}" for i in range(100)]
        # Down 10 times, then enter.
        keys = ["down"] * 10 + ["enter"]
        mock_read_key.side_effect = keys

        with patch("shutil.get_terminal_size", return_value=os.terminal_size((80, 24))):
            res = self.wizard._arrow_menu("Q", opts, default=0)
            self.assertEqual(res, 10)


if __name__ == "__main__":
    unittest.main()
