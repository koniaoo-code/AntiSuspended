import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

SCRIPT = Path(__file__).resolve().parents[1] / "claude-profile.py"
spec = importlib.util.spec_from_file_location("cpm", SCRIPT)
cpm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpm)


def geo(country="DE", timezone="Europe/Berlin", **extra):
    return dict(ip="198.51.100.8", country=country, timezone=timezone,
                provider="fixture", country_name="Fixture", **extra)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home with spaces"
        self.home.mkdir()
        self.m = cpm.Manager(home=self.home, config=self.home / ".config/manager")
        self.real = self.home / "original tools"
        self.real.mkdir()
        for name in ["claude", "claude-desktop"]:
            p = self.real / name
            p.write_text("#!/bin/sh\nexit 0\n")
            p.chmod(0o755)
        self.env = patch.dict(os.environ, {"PATH": str(self.m.bin) + os.pathsep + os.environ["PATH"]})
        self.env.start()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.loc = patch.object(cpm.Manager, "locale_env", return_value=({"PATH": os.environ["PATH"]}, True))
        self.loc.start()

    def tearDown(self):
        self.loc.stop()
        self.output.__exit__(None, None, None)
        self.env.stop()
        self.tmp.cleanup()

    def apply(self, **kw):
        args = dict(auto=False, country="DE", cli=str(self.real / "claude"), desktop=str(self.real / "claude-desktop"))
        args.update(kw)
        self.m.apply(**args)

    def test_apply_repair_is_idempotent_and_restore_preserves_user_data(self):
        self.m.bin.mkdir(parents=True)
        original = self.m.bin / "claude"
        original.write_text("original user launcher\n")
        original.chmod(0o751)
        self.apply()
        profile = self.m.state()["profile"]
        history = Path(profile["code"]) / "user-history.txt"
        history.write_text("keep me")
        self.m.apply(repair=True)
        self.assertEqual(profile, self.m.state()["profile"])
        self.assertEqual(self.m.check()["score"], 10)
        self.m.restore()
        self.assertEqual(original.read_text(), "original user launcher\n")
        self.assertEqual(original.stat().st_mode & 0o777, 0o751)
        self.assertEqual(history.read_text(), "keep me")
        self.assertFalse((self.m.bin / "claude-desktop").exists())

    def test_external_edit_blocks_repair_and_restore(self):
        self.apply()
        p = self.m.bin / "claude"
        p.write_text("manual modification")
        with self.assertRaises(cpm.Error):
            self.m.apply(repair=True)
        with self.assertRaises(cpm.Error):
            self.m.restore()
        self.assertEqual(p.read_text(), "manual modification")
        self.assertLess(self.m.check()["score"], 10)

    def test_rotation_keeps_previous_profile_and_requires_new_path(self):
        self.apply()
        previous = self.m.state()["profile"]
        path = Path(previous["code"]) / ".credentials.json"
        path.write_text('{"fixture": true}')
        self.apply(rotate=True)
        current = self.m.state()
        self.assertNotEqual(current["profile"], previous)
        self.assertIn(previous, current["previous_profiles"])
        self.assertTrue(path.exists())
        self.assertFalse((Path(current["profile"]["code"]) / ".credentials.json").exists())

    def test_import_preserves_existing_profile(self):
        config = self.home / ".config/claude-isolated"
        config.mkdir(parents=True)
        root = self.home / ".local/share/claude-isolated"
        (root / "desktop").mkdir(parents=True)
        (root / "code").mkdir()
        (config / "environment.sh").write_text("export CLAUDE_CONFIG_DIR=" + __import__('shlex').quote(str(root / "code")) + "\n")
        self.apply(import_current=True)
        self.assertEqual(self.m.state()["profile"]["code"], str(root / "code"))

    def test_detect_and_restore_native_symlink_installation(self):
        self.m.bin.mkdir(parents=True)
        p = self.m.bin / "claude"
        p.symlink_to(self.real / "claude")
        self.assertEqual(self.m.executable("cli"), str(self.real / "claude"))
        self.apply()
        self.assertFalse(p.is_symlink())
        self.m.restore()
        self.assertTrue(p.is_symlink())
        self.assertEqual(p.resolve(), self.real / "claude")

    def test_unrelated_symlink_is_not_overwritten(self):
        self.m.bin.mkdir(parents=True)
        target = self.home / "unrelated"
        target.write_text("keep")
        (self.m.bin / "claude").symlink_to(target)
        with self.assertRaises(cpm.Error):
            self.apply()
        self.assertEqual(target.read_text(), "keep")

    def test_run_uses_ip_region_without_rotating_ids(self):
        self.apply()
        state = self.m.state()
        state["auto_ip"] = True
        cpm.save_json(self.m.statefile, state)
        with patch.object(cpm, "lookup_ip", return_value=geo("NL", "Europe/Amsterdam")), patch.object(cpm.os, "execve") as execute:
            self.m.run("desktop", ["--", "claude://example"])
        args = execute.call_args.args
        self.assertEqual(args[1][1:], ["--lang=nl-NL", "claude://example"])
        self.assertEqual(args[2]["XDG_CONFIG_HOME"], state["profile"]["desktop_config"])
        self.assertEqual(self.m.state()["region"]["locale"], "nl_NL.UTF-8")
        self.assertEqual(self.m.state()["profile"], state["profile"])

    def test_network_failure_keeps_last_region_and_emits_warning(self):
        self.apply()
        state = self.m.state()
        state["auto_ip"] = True
        cpm.save_json(self.m.statefile, state)
        err = io.StringIO()
        with patch.object(cpm, "lookup_ip", side_effect=cpm.Error("offline")), patch.object(cpm.os, "execve"), contextlib.redirect_stderr(err):
            self.m.run("cli", ["--version"])
        self.assertIn("последний сохранённый", err.getvalue())
        self.assertEqual(self.m.state()["region"]["country"], "DE")

    def test_runtime_drift_and_missing_path_lower_score(self):
        self.apply()
        (self.m.config / "manager.py").write_text("changed")
        with patch.dict(os.environ, {"PATH": "/usr/bin"}):
            report = self.m.check()
        self.assertFalse(report["checks"][4]["ok"])
        self.assertFalse(report["checks"][9]["ok"])

    def test_argument_quoting_with_home_spaces(self):
        self.apply()
        result = __import__('subprocess').run(["sh", "-n", str(self.m.bin / "claude")], capture_output=True)
        self.assertEqual(result.returncode, 0)
        text = next(p.read_text() for p in self.m.apps.glob("*.desktop") if "claude-desktop" in p.read_text())
        self.assertIn('Exec="' + str(self.m.bin / "claude-desktop") + '" %U', text)


class NetworkTests(unittest.TestCase):
    def test_locale_environment_does_not_forward_ip_lookup_key(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = cpm.Manager(home=Path(directory), config=Path(directory) / "config")
            selected = dict(timezone="Europe/Berlin", locale="C.UTF-8", language="de-DE")
            with patch.dict(os.environ, {"IPAPI_IS_KEY": "fixture-secret"}):
                environment, available = manager.locale_env({"profile": {"code": directory + "/code"}}, selected)
            self.assertNotIn("IPAPI_IS_KEY", environment)
            self.assertEqual(environment["TZ"], "Europe/Berlin")
            self.assertEqual(environment["CLAUDE_CONFIG_DIR"], directory + "/code")
            self.assertTrue(available)

    def test_ip_api_key_is_sent_in_body_not_url(self):
        raw = {"ip": "198.51.100.8", "location": {"country_code": "DE", "timezone": "Europe/Berlin"}, "company": {}, "asn": {}}
        reply = io.BytesIO(json.dumps(raw).encode())
        with patch.dict(os.environ, {"IPAPI_IS_KEY": "fixture-secret"}), patch.object(cpm.urllib.request, "urlopen", return_value=reply) as request:
            result = cpm.lookup_ip()
        req = request.call_args.args[0]
        self.assertNotIn("fixture-secret", req.full_url)
        self.assertEqual(json.loads(req.data)["key"], "fixture-secret")
        self.assertEqual(result["country"], "DE")

    def test_different_exit_ips_are_not_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = cpm.Manager(home=Path(directory), config=Path(directory) / "config")
            first = geo(hosting=None)
            other = geo(hosting=True)
            other["ip"] = "198.51.100.9"
            with patch.dict(os.environ, {}, clear=True), patch.object(cpm, "lookup_ip", side_effect=[first, other]):
                result = manager.ip()
            self.assertIsNone(result["hosting"])
            self.assertIn("разные выходные IP", result["lookup_note"])

    def test_ipquery_unknown_network_does_not_imply_verified_ip(self):
        raw = {"ip": "198.51.100.8", "location": {"country_code": "DE", "timezone": "Europe/Berlin"}, "isp": {"asn": "AS0", "org": ""}, "risk": {"is_datacenter": False, "risk_score": 0}}
        result = cpm.normalize_ip(raw, "ipquery.io")
        self.assertFalse(result["network_record_complete"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cpm.show_ip(result)
        self.assertIn("неполная запись", out.getvalue())
        self.assertNotIn("0/100", out.getvalue())

    def test_free_response_does_not_claim_clean_or_residential(self):
        raw = {"ip": "198.51.100.8", "country_code": "DE", "timezone": {"id": "Europe/Berlin"}, "connection": {"asn": 123}}
        result = cpm.normalize_ip(raw, "ipwho.is")
        for key in ["hosting", "vpn", "proxy", "tor", "abuse"]:
            self.assertIsNone(result[key])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cpm.show_ip(result)
        self.assertIn("Тип сети: нет данных", out.getvalue())
        self.assertIn("Оценка доверия Claude недоступна", out.getvalue())

    def test_keyed_network_flags_remain_individual_facts(self):
        raw = {"ip": "198.51.100.8", "location": {"country_code": "NL", "timezone": "Europe/Amsterdam"}, "company": {"type": "hosting"}, "asn": {"asn": 123}, "is_datacenter": True, "is_vpn": False}
        result = cpm.normalize_ip(raw, "ipapi.is")
        self.assertTrue(result["hosting"])
        self.assertFalse(result["vpn"])
        self.assertIsNone(result["abuse"])

    def test_invalid_remote_timezone_and_boolean_are_not_trusted(self):
        self.assertIsNone(cpm.boolean({"vpn": "false"}, "vpn"))
        with self.assertRaises(cpm.Error):
            cpm.region("DE", "../../etc/passwd")
        with self.assertRaises(cpm.Error):
            cpm.normalize_ip({"ip": "not an IP"}, "ipwho.is")

    def test_actual_ip_timezone_takes_precedence_over_country_default(self):
        self.assertEqual(cpm.region("US", "America/Los_Angeles")["timezone"], "America/Los_Angeles")


class FakeScreen:
    def __init__(self, height=30, width=100, keys=()):
        self.height, self.width = height, width
        self.keys = list(keys)
        self.writes = []

    def getmaxyx(self):
        return self.height, self.width

    def addstr(self, y, x, text, attr=0):
        assert 0 <= y < self.height and 0 <= x < self.width
        cells = sum(0 if cpm.unicodedata.combining(ch) else 2 if cpm.unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
        assert x + cells < self.width, (y, x, text, self.width)
        self.writes.append((y, x, text))

    def getch(self):
        return self.keys.pop(0) if self.keys else ord("q")

    def erase(self):
        self.writes = []

    def refresh(self):
        pass

    def keypad(self, value):
        pass

    def timeout(self, value):
        pass

    def box(self):
        pass


class TerminalTests(unittest.TestCase):
    def setUp(self):
        import curses
        self.curses = Mock(wraps=curses)
        for name in ("A_BOLD", "A_REVERSE", "A_DIM", "KEY_ENTER", "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_PPAGE", "KEY_NPAGE", "KEY_BACKSPACE", "KEY_BTAB"):
            setattr(self.curses, name, getattr(curses, name))
        self.curses.error = curses.error
        self.curses.has_colors.return_value = False
        self.curses.curs_set = Mock()
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Mock()
        self.manager.cachefile = Path(self.tmp.name) / "no-cache.json"
        self.manager.check.return_value = {"installed": True, "score": 10,
            "region": cpm.region("DE"), "auto_ip": True, "clients": {"cli": True, "desktop": True},
            "checks": [{"name": str(i), "ok": True} for i in range(10)], "cli_ids": {"userID": "different"}}
        self.manager.state.return_value = {"auto_ip": True, "region": cpm.region("DE")}
        self.manager.legacy.return_value = None
        self.manager.ip.return_value = geo()

    def tearDown(self):
        self.tmp.cleanup()

    def ui(self):
        ui = cpm.TerminalUI(self.manager)
        ui.curses = self.curses
        ui.good = ui.bad = ui.accent = 0
        return ui

    def test_responsive_layout_all_actions_and_small_terminal(self):
        for height, width in [(40, 120), (24, 84), (24, 80), (18, 52), (12, 40)]:
            for selected in range(7):
                ui = self.ui()
                ui.selected = selected
                ui.draw(FakeScreen(height, width))

    def test_keyboard_navigation_and_exit(self):
        c = self.curses
        ui = self.ui()
        screen = FakeScreen(keys=[c.KEY_DOWN, 9, c.KEY_BTAB, ord("7"), c.KEY_UP, ord("q")])
        ui.main(screen, c)
        self.assertEqual(ui.selected, 5)

    def test_country_picker_accepts_country_code(self):
        ui = self.ui()
        self.curses.newwin.return_value = FakeScreen(21, 65, [ord("N"), ord("L"), 10])
        self.assertEqual(ui.choose_country(FakeScreen()), "NL")

    def test_confirm_defaults_to_cancel_and_tab_accepts(self):
        ui = self.ui()
        self.curses.newwin.return_value = FakeScreen(10, 68, [10])
        self.assertFalse(ui.confirm(FakeScreen(), "Confirm", "Explanation", "Proceed"))
        self.curses.newwin.return_value = FakeScreen(10, 68, [9, 10])
        self.assertTrue(ui.confirm(FakeScreen(), "Confirm", "Explanation", "Proceed"))

    def test_every_action_dispatches_to_backend(self):
        methods = ["show_status", "ip", "apply", "apply", "apply", "apply", "restore"]
        for choice, method in enumerate(methods):
            self.manager.reset_mock()
            ui = self.ui()
            ui.selected = choice
            ui.choose_country = lambda _: "NL"
            ui.confirm = lambda *args: True
            ui.activate(FakeScreen())
            ui.job.join(2)
            self.assertFalse(ui.job.is_alive())
            self.assertFalse(ui.completed[2], ui.completed)
            getattr(self.manager, method).assert_called_once()
            if choice == 3:
                self.assertEqual(self.manager.apply.call_args.kwargs["country"], "NL")
            if choice == 4:
                self.assertTrue(self.manager.apply.call_args.kwargs["repair"])
            if choice == 5:
                self.assertTrue(self.manager.apply.call_args.kwargs["rotate"])

    def test_worker_error_is_shown_as_error_report(self):
        self.manager.ip.side_effect = cpm.Error("API unavailable")
        ui = self.ui()
        ui.selected = 1
        ui.activate(FakeScreen())
        ui.job.join(2)
        self.assertTrue(ui.completed[2])
        self.assertIn("Ошибка: API unavailable", ui.completed[1])

    def test_unicode_cell_clipping(self):
        self.assertEqual(cpm.terminal_clip("界abc", 3), "界a")
        self.assertEqual(cpm.terminal_clip("abc", 0), "")

    def test_ip_details_toggle_and_incomplete_score_is_hidden(self):
        ui = self.ui()
        ui.cache = geo(provider_risk=0, network_record_complete=False)
        ui.main(FakeScreen(keys=[ord("2"), ord("d"), ord("q")]), self.curses)
        self.assertTrue(ui.ip_details)
        output = "\n".join(ui.outputs[1])
        self.assertIn("Выходной IP запроса", output)
        self.assertNotIn("0/100", output)

    def test_positive_vpn_flag_not_hidden_by_incomplete_network_record(self):
        result = geo(vpn=True, proxy=False, tor=False, network_record_complete=False, provider_risk=0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cpm.show_ip(result)
        self.assertIn("VPN: есть отметка в базе", out.getvalue())
        self.assertNotIn("0/100", out.getvalue())

    def test_ready_overview_leads_with_next_step_and_client_groups(self):
        ui = self.ui()
        rows = ui.overview()
        text = "\n".join(line for line, tone in rows)
        self.assertTrue(text.startswith("Что делать сейчас\nМожно пользоваться Claude."))
        self.assertIn("введи claude в новом терминале", text)
        self.assertIn(("Desktop: готов, отдельный каталог", "good"), rows)
        self.assertIn(("CLI: готов, отдельный каталог", "good"), rows)
        self.assertNotIn("/10", text)

    def test_first_setup_has_explicit_menu_instruction(self):
        ui = self.ui()
        ui.report = {"installed": False}
        text = "\n".join(line for line, tone in ui.content())
        self.assertIn("Выбери 3, затем Enter", text)
        self.assertNotIn("Можно пользоваться", text)

    def test_failed_check_changes_overview_and_explains_repair(self):
        ui = self.ui()
        ui.report["checks"][4] = {"ok": False, "name": "Команды недоступны"}
        self.assertFalse(ui.all_ok())
        rows = ui.overview()
        self.assertIn(("Нужно исправить: Команды недоступны", "bad"), rows)
        self.assertTrue(any("Выбери 5, Enter" in text for text, tone in rows))
        details = ui.diagnostics()
        self.assertIn(("Команды и ярлыки", "heading"), details)

    def test_unknown_network_is_amber_and_keeps_positive_flags(self):
        ui = self.ui()
        ui.cache = geo(network_record_complete=False, provider_risk=0, vpn=False, proxy=False, tor=False)
        rows = ui.network_view()
        self.assertIn(("VPN / прокси / Tor: недостаточно данных", "warn"), rows)
        self.assertTrue(any("Домашний IP" in text and tone == "warn" for text, tone in rows))
        self.assertFalse(any("0/100" in text for text, tone in rows))
        ui.cache["vpn"] = True
        self.assertIn(("Есть отметки: VPN", "warn"), ui.network_view())

    def test_success_summary_hides_logs_until_details_requested(self):
        ui = self.ui()
        ui.selected = ui.last_action = 5
        ui.outputs[5] = ["technical-path"]
        rows = ui.content()
        self.assertEqual(rows[0][1], "good")
        self.assertTrue(any("войд" in text for text, tone in rows))
        self.assertNotIn(("technical-path", "normal"), rows)
        ui.details = True
        self.assertIn(("technical-path", "normal"), ui.content())

    def test_extended_palette_uses_distinct_semantic_colours(self):
        ui = self.ui()
        self.curses.has_colors.return_value = True
        self.curses.COLORS = 256
        self.curses.start_color = Mock()
        self.curses.use_default_colors = Mock()
        self.curses.init_pair = Mock()
        self.curses.color_pair.side_effect = lambda value: value * 256
        with patch.dict(os.environ, {"COLORFGBG": "15;0"}, clear=True):
            ui.main(FakeScreen(keys=[ord("q")]), self.curses)
        self.assertEqual([call.args for call in self.curses.init_pair.call_args_list],
                         [(1, 114, -1), (2, 217, -1), (3, 222, -1), (4, 117, -1)])
        self.assertEqual(len({ui.good, ui.bad, ui.warn, ui.accent}), 4)

    def test_no_color_preserves_text_status(self):
        ui = self.ui()
        self.curses.has_colors.return_value = True
        screen = FakeScreen(keys=[ord("q")])
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            ui.main(screen, self.curses)
        self.curses.init_pair.assert_not_called()
        self.assertTrue(any("ГОТОВО" in text for y, x, text in screen.writes))


if __name__ == "__main__":
    unittest.main()
