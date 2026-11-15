#!/usr/bin/env python3
"""Linux: separate local Claude profiles, region settings, and public IP diagnostics.

Python 3.9+. No third-party packages. Does not impersonate identities, change
hardware IDs, or estimate Anthropic's private anti-abuse decisions.
"""
import argparse
import contextlib
import hashlib
import io
import ipaddress
import json
import locale
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.request
import uuid
import unicodedata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

VERSION = "1.2.0"
MARKER = "# claude-profile-manager v1"
AUTH_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_SESSION_ACCESS_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR")
# A country can have several languages/time zones. These are explicit defaults;
# automatic mode uses the time zone returned for the actual exit IP.
REGIONS = {
    "DE": ("Europe/Berlin", "de_DE", "de-DE"),
    "NL": ("Europe/Amsterdam", "nl_NL", "nl-NL"),
    "AT": ("Europe/Vienna", "de_AT", "de-AT"),
    "CH": ("Europe/Zurich", "de_CH", "de-CH"),
    "BE": ("Europe/Brussels", "nl_BE", "nl-BE"),
    "FR": ("Europe/Paris", "fr_FR", "fr-FR"),
    "GB": ("Europe/London", "en_GB", "en-GB"),
    "IE": ("Europe/Dublin", "en_IE", "en-IE"),
    "US": ("America/New_York", "en_US", "en-US"),
    "CA": ("America/Toronto", "en_CA", "en-CA"),
    "PL": ("Europe/Warsaw", "pl_PL", "pl-PL"),
    "CZ": ("Europe/Prague", "cs_CZ", "cs-CZ"),
    "FI": ("Europe/Helsinki", "fi_FI", "fi-FI"),
    "SE": ("Europe/Stockholm", "sv_SE", "sv-SE"),
    "NO": ("Europe/Oslo", "nb_NO", "nb-NO"),
    "DK": ("Europe/Copenhagen", "da_DK", "da-DK"),
    "EE": ("Europe/Tallinn", "et_EE", "et-EE"),
    "LV": ("Europe/Riga", "lv_LV", "lv-LV"),
    "LT": ("Europe/Vilnius", "lt_LT", "lt-LT"),
    "ES": ("Europe/Madrid", "es_ES", "es-ES"),
    "PT": ("Europe/Lisbon", "pt_PT", "pt-PT"),
    "IT": ("Europe/Rome", "it_IT", "it-IT"),
    "RO": ("Europe/Bucharest", "ro_RO", "ro-RO"),
    "BG": ("Europe/Sofia", "bg_BG", "bg-BG"),
    "GR": ("Europe/Athens", "el_GR", "el-GR"),
    "TR": ("Europe/Istanbul", "tr_TR", "tr-TR"),
    "UA": ("Europe/Kyiv", "uk_UA", "uk-UA"),
    "RU": ("Europe/Moscow", "ru_RU", "ru-RU"),
    "JP": ("Asia/Tokyo", "ja_JP", "ja-JP"),
    "KR": ("Asia/Seoul", "ko_KR", "ko-KR"),
    "SG": ("Asia/Singapore", "en_SG", "en-SG"),
    "AU": ("Australia/Sydney", "en_AU", "en-AU"),
    "NZ": ("Pacific/Auckland", "en_NZ", "en-NZ"),
    "BR": ("America/Sao_Paulo", "pt_BR", "pt-BR"),
    "IN": ("Asia/Kolkata", "en_IN", "en-IN"),
}


class Error(Exception):
    pass


def clean(value):
    return "".join(c for c in str(value) if c.isprintable())[:500]


def read_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except (ValueError, OSError) as e:
        raise Error(f"Не удалось прочитать {path}: {type(e).__name__}") from e


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_file(path, content, mode=0o600):
    if path.is_symlink():
        raise Error(f"Отказ от записи поверх символической ссылки: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".cpm-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_json(path, data):
    write_file(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())


def private_dir(path):
    if path.is_symlink():
        raise Error(f"Каталог профиля не должен быть ссылкой: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def valid_timezone(value):
    if not isinstance(value, str) or len(value) > 100:
        return False
    try:
        ZoneInfo(value)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def region(country, timezone=None):
    country = (country or "").upper()
    if country not in REGIONS:
        raise Error(f"Для страны {clean(country)} нет однозначного языкового шаблона. "
                    "Выбери --country вручную из: " + ", ".join(REGIONS))
    tz, loc, language = REGIONS[country]
    if timezone is not None:
        if not valid_timezone(timezone):
            raise Error("Провайдер вернул неизвестный часовой пояс")
        tz = timezone
    return {"country": country, "timezone": tz, "locale": loc + ".UTF-8", "language": language}


def boolean(data, key):
    value = data.get(key)
    return value if isinstance(value, bool) else None


def obj(value):
    return value if isinstance(value, dict) else {}


def normalize_ip(data, provider):
    if not isinstance(data, dict) or data.get("success") is False or data.get("error"):
        raise Error("Сервис проверки IP вернул ошибку")
    try:
        ip = str(ipaddress.ip_address(data.get("ip", "")))
    except ValueError as e:
        raise Error("Сервис проверки IP не вернул корректный адрес") from e
    if provider == "ipquery.io":
        location = obj(data.get("location"))
        isp = obj(data.get("isp"))
        risk = obj(data.get("risk"))
        score = risk.get("risk_score")
        result = {"country": location.get("country_code"), "country_name": location.get("country"),
                  "city": location.get("city"), "timezone": location.get("timezone"),
                  "asn": isp.get("asn"), "organization": isp.get("org") or isp.get("isp"),
                  "network_type": None, "hosting": boolean(risk, "is_datacenter"),
                  "vpn": boolean(risk, "is_vpn"), "proxy": boolean(risk, "is_proxy"),
                  "tor": boolean(risk, "is_tor"), "mobile": boolean(risk, "is_mobile"),
                  "abuse": boolean(risk, "is_abuser"),
                  "network_record_complete": bool(isp.get("org") or isp.get("isp")) and str(isp.get("asn", "")).removeprefix("AS") not in ("", "0"),
                  "provider_risk": score if type(score) is int and 0 <= score <= 100 else None}
    elif provider == "ipapi.is":
        location = obj(data.get("location"))
        company = data.get("company") or {}
        asn = data.get("asn") or {}
        if not isinstance(company, dict) or not isinstance(asn, dict):
            raise Error("Нет расширенных данных IP: проверь личный ключ IPAPI_IS_KEY")
        result = {"country": location.get("country_code"), "country_name": location.get("country"),
                  "city": location.get("city"), "timezone": location.get("timezone"),
                  "asn": asn.get("asn"), "organization": asn.get("org") or company.get("name"),
                  "network_type": company.get("type") or asn.get("type"),
                  "hosting": boolean(data, "is_datacenter"), "vpn": boolean(data, "is_vpn"),
                  "proxy": boolean(data, "is_proxy"), "tor": boolean(data, "is_tor"),
                  "abuse": boolean(data, "is_abuser"), "mobile": boolean(data, "is_mobile")}
    else:
        connection = obj(data.get("connection"))
        tz = obj(data.get("timezone"))
        security = obj(data.get("security"))
        result = {"country": data.get("country_code"), "country_name": data.get("country"),
                  "city": data.get("city"), "timezone": tz.get("id"),
                  "asn": connection.get("asn"), "organization": connection.get("org") or connection.get("isp"),
                  "network_type": None, "hosting": boolean(security, "hosting"),
                  "vpn": boolean(security, "vpn"), "proxy": boolean(security, "proxy"),
                  "tor": boolean(security, "tor"), "mobile": boolean(security, "mobile"), "abuse": None}
    if not isinstance(result.get("country"), str) or not re.fullmatch(r"[A-Z]{2}", result["country"]):
        raise Error("Сервис проверки IP не вернул страну")
    if not valid_timezone(result.get("timezone")):
        raise Error("Сервис проверки IP не вернул допустимый часовой пояс")
    result.update(ip=ip, provider=provider, checked_at=time.time())
    return result


def lookup_ip(provider=None):
    key = os.environ.get("IPAPI_IS_KEY")
    provider = provider or ("ipapi.is" if key else "ipwho.is")
    if provider == "ipapi.is" and not key:
        raise Error("Для ipapi.is нужен личный ключ в IPAPI_IS_KEY")
    urls = {"ipapi.is": "https://api.ipapi.is/", "ipquery.io": "https://api.ipquery.io/?format=json", "ipwho.is": "https://ipwho.is/"}
    if provider not in urls:
        raise Error("Неизвестный сервис проверки IP")
    request = urllib.request.Request(
        urls[provider],
        data=json.dumps({"key": key}).encode() if provider == "ipapi.is" else None,
        headers={"User-Agent": "ClaudeProfileManager/" + VERSION,
                 "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=7) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise Error("Слишком большой ответ сервиса проверки IP")
        return normalize_ip(json.loads(raw), provider)
    except urllib.error.HTTPError as e:
        raise Error(f"{provider}: HTTP {e.code}; повторные запросы не выполнялись") from None
    except (OSError, ValueError) as e:
        # Exception text may contain request details. Never print a key or URL.
        raise Error(f"{provider}: проверка недоступна ({type(e).__name__})") from None


class Manager:
    def __init__(self, config=None, home=None):
        self.home = Path(home) if home else Path.home()
        self.config = (Path(config) if config else Path(os.environ.get("XDG_CONFIG_HOME", self.home / ".config")) / "claude-profile-manager").expanduser().absolute()
        self.data = (self.home / ".local/share" if home else Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share"))) / "claude-profile-manager"
        self.bin = self.home / ".local/bin"
        self.apps = (self.home / ".local/share" if home else Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share"))) / "applications"
        self.statefile = self.config / "state.json"
        self.cachefile = self.config / "last-ip.json"

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        private_dir(self.config)
        with (self.config / "lock").open("a") as f:
            os.chmod(f.name, 0o600)
            fcntl.flock(f, fcntl.LOCK_EX)
            yield

    def state(self):
        data = read_json(self.statefile)
        if data is not None and (not isinstance(data, dict) or data.get("schema") != 1):
            raise Error("Неизвестный формат настроек; запись остановлена")
        return data

    def executable(self, kind, explicit=None):
        name = "claude" if kind == "cli" else "claude-desktop"
        if explicit:
            p = Path(explicit).expanduser().absolute()
            if p == self.bin / name and not p.is_symlink():
                raise Error("Укажи исходную программу, а не создаваемую обёртку")
            if not p.is_file() or not os.access(p, os.X_OK):
                raise Error("Исходная программа не найдена или не исполняемая: " + str(p))
            return str(p.resolve()) if p.is_symlink() else str(p)
        candidates = [Path(d) / name for d in os.get_exec_path() if d]
        candidates += [Path("/usr/bin") / name, Path("/usr/local/bin") / name]
        for p in candidates:
            if p.absolute() == (self.bin / name).absolute():
                if p.is_symlink() and p.resolve().is_file() and os.access(p, os.X_OK):
                    return str(p.resolve())
                continue
            if p.is_file() and os.access(p, os.X_OK):
                return str(p.absolute())
        return None

    def legacy(self):
        p = self.home / ".config/claude-isolated/environment.sh"
        if not p.is_file():
            return None
        fields = {}
        for line in p.read_text().splitlines():
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if len(tokens) == 2 and tokens[0] == "export" and "=" in tokens[1]:
                k, v = tokens[1].split("=", 1)
                fields[k] = v
        code = Path(fields.get("CLAUDE_CONFIG_DIR", "/nonexistent"))
        desktop = self.home / ".local/share/claude-isolated/desktop"
        if code.is_dir() and desktop.is_dir() and code.is_relative_to(self.home):
            return {"code": str(code), "desktop_config": str(desktop),
                    "root": str(desktop.parent), "cache": str(desktop.parent / "cache"),
                    "state": str(desktop.parent / "state")}
        return None

    def profile(self):
        root = self.data / "profiles" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        return {"root": str(root), "code": str(root / "code"),
                "desktop_config": str(root / "desktop-config"),
                "cache": str(root / "cache"), "state": str(root / "state")}

    def ensure_profile(self, profile):
        for value in dict.fromkeys(profile.values()):
            private_dir(Path(value))

    def launcher(self, kind):
        args = [sys.executable, str(self.config / "manager.py"), "--config", str(self.config), "run", kind]
        return ("#!/bin/sh\n" + MARKER + "\nexec " + shlex.join(args) + ' "$@"\n').encode()

    def desktop_exec(self, command, args):
        # Desktop Entry quoting is not shell quoting; percent signs are field codes.
        quoted = '"' + str(command).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`").replace("%", "%%") + '"'
        return "Exec=" + quoted + (" " + args if args else "")

    def plan(self, state):
        manager_command = "#!/bin/sh\n" + MARKER + "\nexec " + shlex.join([sys.executable, str(self.config / "manager.py"), "--config", str(self.config)]) + ' "$@"\n'
        plan = {self.bin / "claude-profile-manager": (manager_command.encode(), 0o755)}
        if state["executables"].get("cli"):
            plan[self.bin / "claude"] = (self.launcher("cli"), 0o755)
            handler = ("[Desktop Entry]\nName=Claude Code URL Handler\nType=Application\nNoDisplay=true\n" + self.desktop_exec(self.bin / "claude", "--handle-uri %u") + "\nMimeType=x-scheme-handler/claude-cli;\n")
            plan[self.apps / "claude-code-url-handler.desktop"] = (handler.encode(), 0o644)
        if state["executables"].get("desktop"):
            plan[self.bin / "claude-desktop"] = (self.launcher("desktop"), 0o755)
            # Preserve the former local command as an entry point, when present.
            if (self.bin / "claude-ncmm").exists():
                plan[self.bin / "claude-ncmm"] = (self.launcher("desktop"), 0o755)
            sources = {}
            for folder in [Path("/usr/share/applications"), Path("/usr/local/share/applications"), self.apps]:
                if folder.is_dir():
                    for p in folder.glob("*claude*.desktop"):
                        if p.is_file():
                            text = p.read_text(errors="replace")
                            if re.search(r"^Exec=.*(?:claude-desktop|claude-ncmm)", text, re.M):
                                sources[p.name] = text
                    for p in folder.glob("*Claude*.desktop"):
                        if p.is_file():
                            text = p.read_text(errors="replace")
                            if re.search(r"^Exec=.*(?:claude-desktop|claude-ncmm)", text, re.M):
                                sources[p.name] = text
            if not sources:
                sources["claude-profile.desktop"] = "[Desktop Entry]\nName=Claude\nType=Application\nExec=claude-desktop %U\nIcon=claude-desktop\nCategories=Development;\nMimeType=x-scheme-handler/claude;\n"
            for name, text in sources.items():
                lines = []
                for line in text.splitlines():
                    if line == "X-NCMM=true":
                        continue
                    if line.startswith("Exec="):
                        # Replace the first executable token; preserve all original argument text.
                        match = re.match(r'^Exec=(?:"(?:\\.|[^"\\])*"|\S+)(?:\s+(.*))?$', line)
                        if not match:
                            raise Error("Не удалось разобрать команду в " + name)
                        line = self.desktop_exec(self.bin / "claude-desktop", match.group(1) or "")
                    lines.append(line)
                plan[self.apps / name] = (("\n".join(lines) + "\n").encode(), 0o644)
        return plan

    def locale_env(self, state, selected):
        desired = selected["locale"]
        environment = os.environ.copy()
        environment.pop("IPAPI_IS_KEY", None)
        probe = environment.copy()
        probe["LC_ALL"] = desired
        probe["LANG"] = desired
        available = False
        if shutil.which("locale"):
            result = subprocess.run(["locale", "charmap"], env=probe, capture_output=True, timeout=5)
            available = result.returncode == 0 and not result.stderr and b"UTF-8" in result.stdout
        directory = self.config / "locales"
        if not available:
            target = directory / desired
            if not (target / "LC_CTYPE").exists() and shutil.which("localedef"):
                private_dir(directory)
                try:
                    result = subprocess.run(["localedef", "--no-archive", "-i", desired.split(".")[0], "-f", "UTF-8", str(target)], capture_output=True, timeout=30)
                    if result.returncode:
                        shutil.rmtree(target, ignore_errors=True)
                except (OSError, subprocess.TimeoutExpired):
                    shutil.rmtree(target, ignore_errors=True)
            if (target / "LC_CTYPE").exists():
                probe["LOCPATH"] = str(directory)
                result = subprocess.run(["locale", "charmap"], env=probe, capture_output=True, timeout=5) if shutil.which("locale") else None
                available = bool(result and result.returncode == 0 and not result.stderr and b"UTF-8" in result.stdout)
                if available:
                    environment["LOCPATH"] = str(directory)
        chosen = desired if available else "C.UTF-8"
        environment.update(TZ=selected["timezone"], LANG=chosen, LC_ALL=chosen,
                           LANGUAGE=selected["language"].replace("-", "_") + ":" + selected["language"].split("-")[0],
                           CLAUDE_CONFIG_DIR=state["profile"]["code"])
        return environment, available

    def apply(self, auto=True, country=None, cli=None, desktop=None, import_current=False, rotate=False, repair=False, force=False):
        with self.lock():
            old = self.state()
            if repair and not old:
                raise Error("Сначала выполни apply")
            ip = None
            if old and repair:
                selected = old["region"]
                auto = old["auto_ip"]
            elif auto:
                print("Определяю выходной IP через внешний сервис…", file=sys.stderr)
                ip = lookup_ip()
                selected = region(ip["country"], ip["timezone"])
            else:
                selected = region(country or "DE")
            executables = {
                "cli": self.executable("cli", cli) if cli or not old else old["executables"].get("cli"),
                "desktop": self.executable("desktop", desktop) if desktop or not old else old["executables"].get("desktop"),
            }
            if not any(executables.values()):
                raise Error("Claude не найден. Укажи --cli-bin и/или --desktop-bin")
            if rotate:
                profile = self.profile()
            elif old:
                profile = old["profile"]
            else:
                profile = self.legacy() if import_current else None
                if import_current and not profile:
                    raise Error("Прежняя локальная настройка не найдена; ничего не заменено")
                profile = profile or self.profile()
            self.ensure_profile(profile)
            state = {"schema": 1, "version": VERSION, "profile": profile, "region": selected,
                     "auto_ip": auto, "executables": executables,
                     "files": (old or {}).get("files", {}), "previous_profiles": (old or {}).get("previous_profiles", [])}
            if rotate and old:
                state["previous_profiles"] = state["previous_profiles"] + [old["profile"]]
            plan = self.plan(state)
            # Check every conflict before mutating a launcher.
            for p, (content, mode) in plan.items():
                record = state["files"].get(str(p))
                allowed_link = p.is_symlink() and p.parent == self.bin and str(p.resolve()) in executables.values()
                if (p.is_symlink() and not allowed_link) or (p.exists() and not p.is_file()):
                    raise Error("Не заменяю ссылку или специальный файл: " + str(p))
                if record and p.exists() and digest(p.read_bytes()) != record["installed"] and not force:
                    raise Error("Файл изменён извне: " + str(p) + ". Для осознанной замены: repair --force")
            private_dir(self.config / "backups")
            # Record intent before writes, so an interrupted installation remains restorable.
            for p, (content, mode) in plan.items():
                key = str(p)
                if key not in state["files"]:
                    backup = None
                    before_mode = None
                    symlink = os.readlink(p) if p.is_symlink() else None
                    if p.exists() and not symlink:
                        backup = digest(key.encode()) + ".bin"
                        before_mode = stat.S_IMODE(p.stat().st_mode)
                        write_file(self.config / "backups" / backup, p.read_bytes())
                    state["files"][key] = {"backup": backup, "symlink": symlink, "before_mode": before_mode,
                                           "installed": digest(content), "pending": True}
                else:
                    state["files"][key]["previous_installed"] = state["files"][key]["installed"]
                    state["files"][key]["installed"] = digest(content)
                    state["files"][key]["pending"] = True
            save_json(self.statefile, state)
            runtime = Path(__file__).read_bytes()
            write_file(self.config / "manager.py", runtime, 0o700)
            state["runtime_sha256"] = digest(runtime)
            for p, (content, mode) in plan.items():
                if p.is_symlink() and state["files"][str(p)].get("symlink") == os.readlink(p):
                    p.unlink()
                write_file(p, content, mode)
                state["files"][str(p)]["pending"] = False
                save_json(self.statefile, state)
            if ip:
                save_json(self.cachefile, ip)
            _, locale_ok = self.locale_env(state, selected)
            state["locale_available"] = locale_ok
            save_json(self.statefile, state)
            print("Настройка применена. Повторное apply/repair сохраняет текущий профиль.")
            if not locale_ok:
                print("Локаль ОС недоступна: используется C.UTF-8; язык Desktop задан отдельно.")
            print("Открой новый терминал и перезапусти Claude. Прежние данные сохранены.")

    def restore(self, force=False):
        with self.lock():
            state = self.state()
            if not state:
                raise Error("Нет установки для отката")
            for name, record in state["files"].items():
                p = Path(name)
                if p.is_symlink() and not (record.get("pending") and record.get("symlink") == os.readlink(p)):
                    raise Error("Не заменяю ссылку: " + name)
                allowed = [record["installed"], record.get("previous_installed")]
                if p.exists() and not p.is_symlink() and digest(p.read_bytes()) not in allowed and not force:
                    # A pending, untouched target is also safe if it equals its backup.
                    backup = self.config / "backups" / record["backup"] if record["backup"] else None
                    if not (record.get("pending") and backup and p.read_bytes() == backup.read_bytes()):
                        raise Error("Файл изменён извне: " + name + ". Проверь его перед restore --force")
                if record["backup"] and not (self.config / "backups" / record["backup"]).is_file():
                    raise Error("Отсутствует резервная копия: " + name)
            for name, record in state["files"].items():
                p = Path(name)
                if record.get("symlink"):
                    temporary = p.with_name(".cpm-link-" + uuid.uuid4().hex)
                    temporary.symlink_to(record["symlink"])
                    os.replace(temporary, p)
                elif record["backup"]:
                    write_file(p, (self.config / "backups" / record["backup"]).read_bytes(), record["before_mode"])
                elif p.exists():
                    p.unlink()
            self.statefile.rename(self.config / ("restored-" + uuid.uuid4().hex[:8] + ".json"))
            print("Команды и ярлыки восстановлены. Профили и их данные сохранены.")

    def check(self):
        state = self.state()
        if not state:
            return {"installed": False, "legacy_detected": bool(self.legacy()), "score": None, "checks": []}
        records = state["files"]
        intact = lambda p: str(p) in records and p.is_file() and not p.is_symlink() and digest(p.read_bytes()) == records[str(p)]["installed"]
        profile = state["profile"]
        checks = []
        def add(name, ok):
            checks.append({"name": name, "ok": bool(ok)})
        add("CLI: найден исходный исполняемый файл", not state["executables"].get("cli") or os.access(state["executables"]["cli"], os.X_OK))
        add("Desktop: найден исходный исполняемый файл", not state["executables"].get("desktop") or os.access(state["executables"]["desktop"], os.X_OK))
        shared_links = [Path(profile["code"]) / name for name in (".claude.json", ".credentials.json")]
        shared_links += [Path(profile["desktop_config"]) / "Claude" / name for name in ("Cookies", "Local Storage", "Session Storage", "IndexedDB", "Partitions")]
        shared_links += [Path(profile["desktop_config"]) / "Claude"]
        add("Каталоги профиля отделены от стандартных", Path(profile["code"]).absolute() != (self.home / ".claude").absolute() and Path(profile["desktop_config"]).absolute() != (self.home / ".config").absolute() and not any(p.is_symlink() for p in shared_links))
        add("Каталоги профиля закрыты для других пользователей", all(Path(v).is_dir() and not Path(v).is_symlink() and stat.S_IMODE(Path(v).stat().st_mode) & 0o077 == 0 for v in set(profile.values())))
        add("Команды клиентов направлены в менеджер и доступны через PATH", all(intact(Path(p)) for p in records if Path(p).parent == self.bin) and all(shutil.which(name) == str(self.bin / name) for kind, name in [("cli", "claude"), ("desktop", "claude-desktop")] if state["executables"].get(kind)))
        add("Ярлыки и обработчик ссылок не изменены извне", all(intact(Path(p)) for p in records if p.endswith(".desktop")))
        add("Сохранён допустимый часовой пояс", valid_timezone(state["region"].get("timezone")))
        add("Доступна выбранная системная локаль", state.get("locale_available") is True)
        add("В окружении не заданы явные токены входа", not any(os.environ.get(k) for k in AUTH_ENV))
        runtime = self.config / "manager.py"
        add("Резервные копии доступны, установка завершена", all(not r.get("pending") and (not r["backup"] or (self.config / "backups" / r["backup"]).is_file()) for r in records.values()) and runtime.is_file() and digest(runtime.read_bytes()) == state.get("runtime_sha256"))
        ids = {}
        old = read_json(self.home / ".claude.json", {})
        new = read_json(Path(profile["code"]) / ".claude.json", {})
        for key in ["userID", "machineID"]:
            ids[key] = ("ещё не создан" if not new.get(key) else "создан; исходного ID для сравнения нет" if not old.get(key) else "отличается от стандартного профиля" if new.get(key) != old.get(key) else "совпадает со стандартным профилем")
        return {"installed": True, "version": VERSION, "score": sum(c["ok"] for c in checks), "checks": checks,
                "clients": {k: bool(v) for k, v in state["executables"].items()},
                "region": state["region"], "auto_ip": state["auto_ip"], "profile": profile,
                "cli_ids": ids, "running_profile_verified": False,
                "note": "Оценка настроек локальной изоляции. Узнаваемость для Anthropic не измерена."}

    def show_status(self, as_json=False):
        report = self.check()
        if as_json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return report
        if not report["installed"]:
            print("Менеджер не применён.")
            if report["legacy_detected"]:
                print("Найдена прежняя настройка изолированных профилей. Можно импортировать: apply --import-current")
            return report
        print(f"Локальная изоляция: {report['score']}/10")
        print("Это 10 проверок настроек, не рейтинг доверия или анонимности для Claude.")
        print("Настроенные клиенты: " + ", ".join(k for k, v in report["clients"].items() if v))
        for c in report["checks"]:
            print(("[OK] " if c["ok"] else "[!!] ") + c["name"])
        r = report["region"]
        print(f"Последний выбранный регион: {r['country']} | {r['timezone']} | {r['locale']}")
        print("Режим региона: " + ("по IP при запуске" if report["auto_ip"] else "вручную"))
        for key, value in report["cli_ids"].items():
            print(f"CLI {key}: {value}")
        print("Уже запущенные процессы, маршрут до Claude, аппаратный отпечаток и аккаунт этой оценкой не проверяются.")
        return report

    def ip(self, provider=None):
        result = lookup_ip(provider)
        if provider is None and not os.environ.get("IPAPI_IS_KEY"):
            try:
                network = lookup_ip("ipquery.io")
                if network["ip"] != result["ip"]:
                    result["lookup_note"] = "Сервисы видят разные выходные IP; признаки сети не объединены. Проверь маршрутизацию."
                else:
                    for key in ("hosting", "vpn", "proxy", "tor", "mobile", "abuse", "provider_risk", "network_record_complete"):
                        result[key] = network.get(key)
                    result["risk_provider"] = "ipquery.io"
                    result["provider"] = "ipwho.is + ipquery.io"
                    if network["country"] != result["country"] or network["timezone"] != result["timezone"]:
                        result["lookup_note"] = "Базы расходятся по региону; для региона выбран ipwho.is."
            except Error as e:
                result["lookup_note"] = "Дополнительная проверка сети недоступна: " + str(e)
        if self.config.exists():
            save_json(self.cachefile, result)
        return result

    def run(self, kind, arguments):
        state = self.state()
        if not state:
            raise Error("Профиль не настроен; сначала apply")
        executable = state["executables"].get(kind)
        if not executable:
            raise Error("Этот клиент не найден при настройке")
        if not os.access(executable, os.X_OK):
            raise Error("Исходный клиент недоступен: " + executable)
        selected = state["region"]
        if state["auto_ip"]:
            try:
                with self.lock():
                    current = lookup_ip()
                    selected = region(current["country"], current["timezone"])
                    save_json(self.cachefile, current)
                    state["region"] = selected
                    save_json(self.statefile, state)
            except Error as e:
                print("Регион не обновлён: " + str(e) + ". Используется последний сохранённый регион.", file=sys.stderr)
        self.ensure_profile(state["profile"])
        environment, available = self.locale_env(state, selected)
        with self.lock():
            latest = self.state()
            if latest and latest["profile"] == state["profile"] and latest["region"] == selected:
                latest["locale_available"] = available
                save_json(self.statefile, latest)
        if not available:
            print("Системная локаль недоступна; LANG=C.UTF-8. Язык Desktop задан отдельно.", file=sys.stderr)
        if any(environment.get(k) for k in AUTH_ENV):
            print("В окружении задан токен/API-ключ: он определяет используемый аккаунт.", file=sys.stderr)
        if arguments[:1] == ["--"]:
            arguments = arguments[1:]
        if kind == "desktop":
            p = state["profile"]
            environment.update(XDG_CONFIG_HOME=p["desktop_config"], XDG_CACHE_HOME=p["cache"], XDG_STATE_HOME=p["state"])
            lock = Path(p["desktop_config"]) / "Claude/SingletonLock"
            if lock.is_symlink():
                print("Если Desktop уже работает, новые региональные настройки подействуют после его полного завершения и запуска.", file=sys.stderr)
            arguments = ["--lang=" + selected["language"]] + arguments
        print(f"Claude {kind}: {selected['country']}, {selected['timezone']}, {selected['language']}", file=sys.stderr)
        os.umask(0o077)
        os.execve(executable, [executable] + arguments, environment)


def show_ip(result, details=False):
    if details:
        show_ip_details(result)
        return
    incomplete = result.get("network_record_complete") is False
    print("IP: " + clean(result["ip"]))
    print("Регион: " + result["country"] + " · " + clean(result.get("city") or "город неизвестен"))
    print("Провайдер: " + clean(result.get("organization") or "нет данных"))
    print("Часовой пояс: " + result["timezone"])
    kind = "хостинг / дата-центр" if result.get("hosting") is True else "мобильная сеть" if result.get("mobile") is True else "нет данных"
    print("Тип сети: " + kind)
    if all(result.get(key) is None or (incomplete and result.get(key) is False) for key in ("vpn", "proxy", "tor")):
        print("VPN / прокси / Tor: нет данных")
    else:
        for label, key in [("VPN", "vpn"), ("Прокси", "proxy"), ("Tor", "tor")]:
            value = result.get(key)
            print(label + ": " + ("есть отметка в базе" if value is True else "нет данных" if value is None or incomplete else "нет отметки в базе"))
    abuse = result.get("abuse")
    print("Злоупотребления: " + ("есть отметка в базе" if abuse is True else "нет отметки в базе" if abuse is False else "нет данных"))
    score = result.get("provider_risk")
    if incomplete:
        print("Оценка риска: недоступна (неполная запись сети)")
    elif score is not None:
        print(f"Риск по базе {result.get('risk_provider', result['provider'])}: {score}/100")
    else:
        print("Оценка риска: нет данных")
    if result.get("lookup_note"):
        print(clean(result["lookup_note"]))
    print("Оценка доверия Claude недоступна.")


def show_ip_details(result):
    print(f"Выходной IP запроса к {result['provider']}: {clean(result['ip'])}")
    print(f"Регион: {clean(result['country_name'])} ({result['country']}) / {clean(result.get('city') or '?')}")
    print(f"Часовой пояс: {result['timezone']}")
    print(f"Сеть: AS{clean(result.get('asn') or '?').removeprefix('AS')} / {clean(result.get('organization') or '?')}")
    network = result.get("network_type")
    if result.get("hosting") is True:
        description = "хостинг / дата-центр"
    elif result.get("mobile") is True:
        description = "мобильная сеть"
    elif network in ("isp", "business", "education", "government"):
        description = {"isp": "сеть интернет-провайдера; домашнее подключение не подтверждено", "business": "корпоративная сеть", "education": "образовательная сеть", "government": "государственная сеть"}[network]
    else:
        description = "не определён; домашнее подключение не подтверждено"
    print("Тип сети: " + description)
    for key, label in [("hosting", "Хостинг"), ("vpn", "VPN"), ("proxy", "Прокси"), ("tor", "Tor"), ("abuse", "Признак злоупотреблений")]:
        value = result.get(key)
        print(label + ": " + ("есть отметка в базе" if value is True else "нет отметки в этой базе" if value is False else "нет данных"))
    if result.get("provider_risk") is not None and result.get("network_record_complete") is not False:
        print(f"Индекс риска {result.get('risk_provider', result['provider'])}: {result['provider_risk']}/100. Методика провайдера, не вероятность и не рейтинг Claude.")
    if result.get("network_record_complete") is False:
        print("У источника неполная запись сети; его числовой индекс исключён из отчёта.")
    if result.get("lookup_note"):
        print(clean(result["lookup_note"]))
    print("Прогноз доверия Claude: неизвестен. Отсутствие отметок не доказывает отсутствие VPN или жалоб.")
    print("Проверен маршрут к сервису IP, который может отличаться от маршрута приложения к Claude.")
    if all(result.get(k) is None for k in ("hosting", "vpn", "proxy", "tor", "abuse")):
        print("Для расширенной проверки: личный ключ ipapi.is в IPAPI_IS_KEY. Ключ в скрипт не встраивается.")


def parser():
    p = argparse.ArgumentParser(description="Отдельные профили Claude для Linux; проверка настроек и выходного IP.")
    p.add_argument("--config", type=Path, help="Каталог настроек менеджера")
    p.add_argument("--plain", action="store_true", help="Текстовое меню для простых терминалов и скринридеров")
    sub = p.add_subparsers(dest="action")
    status = sub.add_parser("status", help="Проверить настройки без сетевого запроса")
    status.add_argument("--json", action="store_true")
    ip = sub.add_parser("ip", help="Проверить IP через внешний сервис")
    ip.add_argument("--provider", choices=["ipquery.io", "ipwho.is", "ipapi.is"], help="Один источник вместо сравнения ipwho.is + ipquery.io; при IPAPI_IS_KEY используется ipapi.is")
    ip.add_argument("--details", action="store_true", help="Показать источники и ограничения проверки")
    for name in ["apply", "repair", "rotate"]:
        cmd = sub.add_parser(name, help={"apply": "Применить настройки", "repair": "Восстановить обёртки, сохранив профиль", "rotate": "Создать новый пустой профиль; старый сохранить"}[name])
        cmd.add_argument("--country", choices=sorted(REGIONS), help="Ручной регион вместо определения по IP")
        cmd.add_argument("--cli-bin", help="Путь к исходному Claude Code")
        cmd.add_argument("--desktop-bin", help="Путь к исходному Claude Desktop/AppImage")
        cmd.add_argument("--import-current", action="store_true", help="Импортировать прежнюю настройку claude-isolated")
        cmd.add_argument("--force", action="store_true", help="Заменить изменённые извне обёртки")
    restore = sub.add_parser("restore", help="Вернуть прежние команды, сохранив данные профилей")
    restore.add_argument("--force", action="store_true")
    run = sub.add_parser("run", help="Запустить клиент с настройками профиля")
    run.add_argument("kind", choices=["cli", "desktop"])
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    p.add_argument("--version", action="version", version=VERSION)
    return p


def plain_menu(manager):
    while True:
        print("\nClaude Profile Manager " + VERSION)
        print("1. Проверить настройки и оценку локальной изоляции")
        print("2. Проверить выходной IP и признаки сети")
        print("3. Применить настройки, автоматически выбирать регион по IP")
        print("4. Применить настройки с ручным регионом")
        print("5. Повторно применить обёртки, сохранив текущий профиль")
        print("6. Создать новый пустой профиль, сохранив предыдущий")
        print("7. Вернуть прежние команды и ярлыки")
        print("0. Выход")
        choice = input("> ").strip()
        try:
            if choice == "0":
                return
            if choice == "1":
                manager.show_status()
            elif choice == "2":
                show_ip(manager.ip())
            elif choice == "3":
                manager.apply(auto=True, import_current=bool(not manager.state() and manager.legacy()))
            elif choice == "4":
                print("Страны: " + ", ".join(REGIONS))
                country = input("Код страны: ").strip().upper()
                if country not in REGIONS:
                    raise Error("Неизвестный код страны")
                manager.apply(auto=False, country=country, import_current=bool(not manager.state() and manager.legacy()))
            elif choice == "5":
                manager.apply(repair=True)
            elif choice == "6":
                print("Потребуется новый вход. Существующий профиль останется на диске.")
                if input("Создать пустой профиль? [y/N] ").strip().lower() in ("y", "yes", "д", "да"):
                    old = manager.state()
                    manager.apply(auto=old["auto_ip"] if old else True, country=old["region"]["country"] if old else None, rotate=True)
            elif choice == "7":
                manager.restore()
            else:
                print("Выбери пункт от 0 до 7.")
        except Error as e:
            print("Ошибка: " + clean(e), file=sys.stderr)


def terminal_clip(value, width):
    """Clip terminal cells, including wide and combining Unicode characters."""
    result, cells = [], 0
    for char in str(value):
        if not char.isprintable():
            continue
        count = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        if cells + count > max(0, width):
            break
        result.append(char)
        cells += count
    return "".join(result)


class TerminalUI:
    ACTIONS = [
        ("Обзор и что делать", "Проверить настройки и показать следующий шаг."),
        ("Проверить IP", "Запросить выходной IP, регион и сведения о сети. Два внешних сервиса; их данные могут расходиться."),
        ("Настроить по IP", "Выбирать часовой пояс и язык по выходному IP при запуске Claude. Текущий профиль и авторизация сохранятся."),
        ("Задать страну", "Задать страну вручную. При запуске клиента сетевой запрос для выбора региона не потребуется."),
        ("Починить запуск", "Повторно создать команды и ярлыки. Текущие ID, история и авторизация сохранятся."),
        ("Новый профиль", "Создать пустые каталоги для Desktop и CLI. Потребуется новый вход; предыдущий профиль останется на диске."),
        ("Откатить установку", "Вернуть команды и ярлыки из резервной копии. Данные профилей останутся на диске."),
    ]
    HINTS = ["С чего начать", "Адрес, регион, сеть", "Регион при запуске", "Регион вручную", "Сбой команды/ярлыка", "Пустой, нужен вход", "Прежние команды"]
    WHEN = {2: "Для первой настройки или смены региона вслед за VPN.",
            3: "Если хочешь сам выбрать язык и часовой пояс.",
            4: "Если команда или ярлык запускает Claude неправильно.",
            5: "Если нужен отдельный пустой профиль без истории и входа.",
            6: "Если хочешь прекратить использовать менеджер."}
    FIXES = {0: "Проверь установку CLI; затем выбери 5, Enter.",
             1: "Проверь установку Desktop; затем выбери 5, Enter.",
             2: "Проверь каталоги профилей в подробностях (d).",
             3: "Проверь права каталогов профилей в подробностях (d).",
             4: "Выбери 5, Enter. Если не помогло, проверь PATH (d).",
             5: "Выбери 5, Enter, чтобы восстановить ярлыки.",
             6: "Выбери 3 или 4 и задай регион заново.",
             7: "Установи исходники локалей своего Linux и выбери 5, Enter.",
             8: "Убери переменные токенов из окружения этого терминала (список: d).",
             9: "Выбери 5, Enter. При ошибке посмотри подробности (d)."}

    def __init__(self, manager):
        self.manager = manager
        self.selected = 0
        self.scroll = 0
        self.outputs = {}
        self.report = {}
        self.cache = None
        self.job = None
        self.completed = None
        self.message = "Цифра выбирает пункт, Enter выполняет."
        self.failed = False
        self.ip_details = False
        self.details = False
        self.last_action = None
        self.good = self.bad = self.warn = self.accent = 0
        self.refresh_state()

    def refresh_state(self):
        try:
            self.report = self.manager.check()
            self.cache = read_json(self.manager.cachefile) or self.cache
            if self.report.get("installed"):
                rows = ["Проверки локальной конфигурации", ""]
                labels = ["CLI: исходная программа найдена", "Desktop: исходная программа найдена",
                          "Профили используют отдельные каталоги", "Доступ к профилям ограничен владельцем",
                          "Команды подключены и доступны в PATH", "Ярлыки и ссылки подключены",
                          "Часовой пояс существует", "Системная локаль доступна",
                          "В окружении нет токенов входа", "Резервная копия и код менеджера целы"]
                for i, check in enumerate(self.report["checks"]):
                    rows.append(("[OK] " if check["ok"] else "[!!] ") + (labels[i] if i < len(labels) else check["name"]))
                rows += ["", "Локальные ID CLI"]
                rows += [key + ": " + value for key, value in self.report["cli_ids"].items()]
                rows += ["", "Аккаунт, KYC, IP и аппаратный отпечаток этой оценкой не проверяются."]
                self.outputs[0] = rows
            else:
                self.outputs[0] = ["Настройка ещё не применена.", "", "Выбери «Авто по IP» или «Выбрать регион»."]
                if self.report.get("legacy_detected"):
                    self.outputs[0] += ["", "Найден прежний изолированный профиль. Он будет импортирован с сохранением данных."]
            if self.cache and 1 not in self.outputs:
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    show_ip(self.cache, details=self.ip_details)
                checked = self.cache.get("checked_at")
                timestamp = time.strftime("%d.%m %H:%M", time.localtime(checked)) if isinstance(checked, (int, float)) else "неизвестно"
                self.outputs[1] = ["Сохранённый отчёт: " + timestamp, "Enter запросит свежие данные.", ""] + out.getvalue().splitlines()
        except (Error, OSError) as e:
            self.report = {"installed": False}
            self.failed = True
            self.message = "Не удалось прочитать настройки"
            self.outputs[0] = [str(e)]

    def all_ok(self):
        checks = self.report.get("checks", [])
        return bool(self.report.get("installed") and checks and all(check["ok"] for check in checks))

    def overview(self):
        """Rows carry meaning and colour independently of backend log wording."""
        if not self.report.get("installed"):
            rows = [("Что делать сейчас", "heading"),
                    ("Выбери 3, затем Enter: настроить по текущему IP.", "accent"),
                    ("Или 4, Enter: выбрать страну вручную.", "normal"), ("", "normal")]
            if self.report.get("legacy_detected"):
                rows += [("Найден прежний профиль. Настройка сохранит его данные.", "warn")]
            return rows
        checks = self.report.get("checks", [])
        failures = [(i, check) for i, check in enumerate(checks) if not check["ok"]]
        rows = [("Что делать сейчас", "heading")]
        if failures:
            index, check = failures[0]
            rows += [("Нужно исправить: " + check["name"], "bad"), (self.FIXES.get(index, "Открой подробности: d."), "accent")]
        else:
            rows += [("Можно пользоваться Claude.", "good"),
                     ("Desktop: открой обычный ярлык.", "normal") if self.report.get("clients", {}).get("desktop") else ("Desktop не настроен.", "warn"),
                     ("CLI: введи claude в новом терминале.", "normal") if self.report.get("clients", {}).get("cli") else ("CLI не настроен.", "warn"),
                     ("Для проверки сети: выбери 2, затем Enter.", "accent")]
        rows += [("", "normal"), ("Профили и запуск", "heading")]
        groups = [("Desktop", "desktop", [1, 2, 3, 5]), ("CLI", "cli", [0, 2, 3, 4, 8])]
        for title, key, indices in groups:
            if not self.report.get("clients", {}).get(key):
                rows.append((title + ": не настроен", "warn"))
            elif all(i < len(checks) and checks[i]["ok"] for i in indices):
                rows.append((title + ": готов, отдельный каталог", "good"))
            else:
                rows.append((title + ": есть проблема с настройками", "bad"))
        rows += [("", "normal"), ("Язык и время Claude", "heading")]
        selected = self.report.get("region", {})
        rows += [(selected.get("country", "?") + " · " + selected.get("timezone", "?"), "normal"),
                 ("Язык: " + selected.get("language", "?"), "normal"),
                 ("Обновляются по IP при запуске." if self.report.get("auto_ip") else "Заданы вручную; смена страны: 4, Enter.", "normal")]
        rows += [("", "normal"), ("Границы проверки", "heading"),
                 ("Проверены локальные настройки. Запущенные процессы и узнаваемость для Claude не проверены.", "normal"),
                 ("d: проверки по группам и локальные ID", "accent")]
        return rows

    def diagnostics(self):
        rows = []
        checks = self.report.get("checks", [])
        for heading, indices in [("Программы", [0, 1]), ("Профили", [2, 3, 8]),
                                 ("Команды и ярлыки", [4, 5]), ("Язык и время", [6, 7]), ("Резервная копия", [9])]:
            rows.append((heading, "heading"))
            for index in indices:
                if index < len(checks):
                    check = checks[index]
                    rows.append((("OK: " if check["ok"] else "ПРОБЛЕМА: ") + check["name"], "good" if check["ok"] else "bad"))
                    if not check["ok"]:
                        rows.append((self.FIXES[index], "normal"))
            rows.append(("", "normal"))
        rows.append(("Локальные ID CLI", "heading"))
        for key, value in self.report.get("cli_ids", {}).items():
            tone = "good" if value.startswith("отличается") else "warn"
            rows.append((key + ": " + value, tone))
        rows += [("ID могут появиться после первого запуска CLI.", "normal"),
                 ("Переменные входа: " + ", ".join(AUTH_ENV), "normal"),
                 ("Это проверка настроек, а не оценка анонимности.", "normal")]
        return rows

    def network_view(self):
        r = self.cache
        if not r:
            return [("Проверка ещё не запускалась", "warn"),
                    ("Нажми Enter. Обычно это занимает несколько секунд.", "accent"),
                    ("", "normal"), ("Что узнаем", "heading"),
                    ("Выходной IP, страну, провайдера и доступные отметки VPN / прокси.", "normal"),
                    ("Запрос уйдёт в два внешних сервиса определения IP.", "normal")]
        checked = r.get("checked_at")
        stamp = time.strftime("%d.%m %H:%M", time.localtime(checked)) if isinstance(checked, (int, float)) else "время неизвестно"
        rows = [("Сохранённая проверка · " + stamp, "heading"),
                ("Enter: проверить сейчас", "accent"), ("", "normal"),
                ("Адрес и регион", "heading"), ("IP: " + clean(r.get("ip", "?")), "normal"),
                (r.get("country", "?") + " · " + clean(r.get("city") or "город неизвестен"), "normal"),
                ("Провайдер: " + clean(r.get("organization") or "нет данных"), "normal")]
        selected = self.report.get("region", {})
        if selected:
            same = selected.get("timezone") == r.get("timezone") and selected.get("country") == r.get("country")
            rows.append(("Регион совпадает с настройками." if same else "Регион отличается. Для настройки по IP: 3, Enter.", "good" if same else "warn"))
        rows += [("", "normal"), ("Что известно о сети", "heading")]
        incomplete = r.get("network_record_complete") is False
        kind = "хостинг / дата-центр" if r.get("hosting") is True else "мобильная сеть" if r.get("mobile") is True else "не определён"
        rows.append(("Тип сети: " + kind, "warn" if kind == "не определён" else "normal"))
        positives = [label for label, key in [("VPN", "vpn"), ("прокси", "proxy"), ("Tor", "tor")] if r.get(key) is True]
        if positives:
            rows.append(("Есть отметки: " + ", ".join(positives), "warn"))
        elif incomplete or any(r.get(key) is None for key in ("vpn", "proxy", "tor")):
            rows.append(("VPN / прокси / Tor: недостаточно данных", "warn"))
        else:
            rows.append(("VPN / прокси / Tor: нет отметок в этой базе", "normal"))
        abuse = r.get("abuse")
        rows.append(("Жалобы: " + ("есть отметка" if abuse is True else "нет отметок в этой базе" if abuse is False and not incomplete else "нет данных"), "warn" if abuse is True or abuse is None or incomplete else "normal"))
        rows += [("", "normal"), ("Как это понимать", "heading")]
        if incomplete:
            rows.append(("База не распознала сеть. Домашний IP и отсутствие VPN не подтверждены.", "warn"))
        else:
            rows.append(("Отсутствие отметок не доказывает домашний IP или отсутствие VPN.", "normal"))
        rows += [("Рейтинг доверия Claude неизвестен.", "normal"),
                 ("d: источники и технические подробности", "accent")]
        if r.get("lookup_note"):
            rows += [("", "normal"), (clean(r["lookup_note"]), "warn")]
        return rows

    def content(self):
        if self.job and self.selected == self.job_choice:
            return [("Подожди, выполняется запрос…", "accent"), ("Результат появится здесь.", "normal")]
        details = self.ip_details if self.selected == 1 else self.details
        if self.last_action == self.selected and self.failed:
            lines = self.outputs.get(self.selected, [])
            if details:
                return [(line, "bad" if line.startswith("Ошибка:") else "normal") for line in lines]
            error = next((line for line in reversed(lines) if line.startswith("Ошибка:")), "Действие не выполнено.")
            return [("Не удалось выполнить действие", "bad"), (error, "normal"), ("", "normal"),
                    ("Настройки можно проверить в пункте 1.", "normal"), ("Enter: повторить · d: полный вывод", "accent")]
        if self.selected == 0:
            return self.diagnostics() if self.details and self.report.get("installed") else self.overview()
        if self.selected == 1:
            if self.ip_details and self.cache:
                return [(line, "normal") for line in self.outputs.get(1, [])]
            return self.network_view()
        if details and self.selected in self.outputs:
            return [(line, "normal") for line in self.outputs[self.selected]]
        if self.last_action == self.selected:
            next_step = "Полностью закрой Desktop и открой его заново. CLI запускай командой claude."
            if self.selected == 5:
                next_step = "Открой Claude и войди в аккаунт. Предыдущий профиль сохранён."
            elif self.selected == 6:
                next_step = "Команды возвращены к состоянию до установки менеджера."
            return [("Готово: " + self.ACTIONS[self.selected][0].lower(), "good"),
                    ("", "normal"), ("Следующий шаг", "heading"), (next_step, "normal"),
                    ("", "normal"), ("1: обзор настроек · d: полный вывод", "accent")]
        return [("Когда это нужно", "heading"), (self.WHEN[self.selected], "normal"),
                ("", "normal"), ("Что произойдёт", "heading"), (self.ACTIONS[self.selected][1], "normal"),
                ("", "normal"), ("Enter: " + self.ACTIONS[self.selected][0].lower(), "accent")]

    def paint(self, window, y, x, value, width=None, attr=0):
        h, w = window.getmaxyx()
        if not (0 <= y < h and 0 <= x < w - 1):
            return
        available = min(w - x - 1, width if width is not None else w)
        text = terminal_clip(value, available)
        if not text:
            return
        try:
            window.addstr(y, x, text, attr)
        except self.curses.error:
            pass  # A resize can occur between reading the size and writing.

    def wrapped(self, lines, width):
        result = []
        for line in lines:
            result.extend(textwrap.wrap(str(line), max(1, width), replace_whitespace=False) or [""])
        return result

    def draw(self, screen):
        c = self.curses
        screen.erase()
        h, w = screen.getmaxyx()
        if w < 52 or h < 18:
            self.paint(screen, 1, 1, "Claude Profiles", attr=c.A_BOLD)
            self.paint(screen, 3, 1, "Нужно окно от 52 столбцов и 18 строк.")
            self.paint(screen, 5, 1, f"Сейчас: {w} × {h}. Увеличь окно; q: выход.")
            screen.refresh()
            return
        self.paint(screen, 1, 2, "Claude Profiles", attr=c.A_BOLD)
        self.paint(screen, 1, w - 11, "v" + VERSION, attr=c.A_DIM)
        installed = self.report.get("installed")
        state = self.report.get("region", {})
        ready = self.all_ok()
        status = "ГОТОВО  Профили настроены" if ready else "НУЖНО ИСПРАВИТЬ  Открой обзор: 1" if installed else "НАЧНИ ЗДЕСЬ  Настройка ещё не применена"
        self.paint(screen, 3, 2, status, attr=c.A_BOLD | (self.good if ready else self.bad if installed else self.warn))
        if installed:
            mode = "по IP" if self.report.get("auto_ip") else "вручную"
            self.paint(screen, 4, 2, f"{state.get('country', '?')}  ·  {state.get('timezone', '?')}  ·  {state.get('language', '?')}  ·  {mode}")
            self.paint(screen, 5, 2, "Зелёный: готово", attr=self.good)
            self.paint(screen, 5, 19, "Жёлтый: нет данных", attr=self.warn)
            if w >= 76:
                self.paint(screen, 5, 39, "Красный: нужна правка", attr=self.bad)
        else:
            self.paint(screen, 4, 2, "Начни с автоматического или ручного выбора региона.")
        split = w >= 76
        left = 27
        top = 8
        if split:
            for y in range(top, h - 4):
                self.paint(screen, y, left + 2, "│", attr=c.A_DIM)
            detail_x, detail_y, detail_w = left + 5, top, w - left - 8
            menu_y = [top + i * 3 for i in range(7)] if h >= 36 else [top + i * 2 for i in range(7)] if h >= 29 else [top + i for i in range(7)]
        else:
            compact = h < 24
            start = max(0, min(self.selected - 1, 4)) if compact else 0
            menu_y = {i: 7 + i - start for i in range(start, min(7, start + 3) if compact else 7)}
            detail_x, detail_y, detail_w = 2, 11 if compact else 15, w - 4
        for i, (label, _) in enumerate(self.ACTIONS):
            if not split and i not in menu_y:
                continue
            attr = c.A_REVERSE | c.A_BOLD if i == self.selected else 0
            text = f" {i + 1}  {label}"
            self.paint(screen, menu_y[i], 2, text.ljust(left - 1), left - 1 if split else w - 4, attr)
            if split and h >= 36:
                self.paint(screen, menu_y[i] + 1, 7, self.HINTS[i], left - 6, c.A_DIM)
        title, explanation = self.ACTIONS[self.selected]
        self.paint(screen, detail_y, detail_x, title, detail_w, c.A_BOLD | self.accent)
        lines = []
        for text, tone in self.content():
            lines.extend((line, tone) for line in self.wrapped([text], detail_w))
        visible = max(0, h - 6 - detail_y)
        self.scroll = max(0, min(self.scroll, max(0, len(lines) - visible)))
        styles = {"normal": 0, "heading": c.A_BOLD, "good": self.good, "bad": self.bad,
                  "warn": self.warn, "accent": self.accent | c.A_BOLD}
        for i, (line, tone) in enumerate(lines[self.scroll:self.scroll + visible]):
            self.paint(screen, detail_y + 2 + i, detail_x, line, detail_w, styles[tone])
        if len(lines) > visible and visible:
            position = f"{self.scroll + 1}–{min(len(lines), self.scroll + visible)}/{len(lines)}  PgUp/PgDn"
            self.paint(screen, h - 4, detail_x, position, detail_w, c.A_DIM)
        self.paint(screen, h - 2, 2, self.message, w - 4, self.bad if self.failed else 0)
        help_text = "↑↓/1–7 выбор · Enter · d детали · PgDn ниже · q выход" if w >= 76 else "↑↓ выбор · Enter · d детали · PgDn · q выход"
        self.paint(screen, h - 1, 2, help_text, w - 4, c.A_DIM)
        screen.refresh()

    def choose_country(self, screen):
        c = self.curses
        countries = sorted(REGIONS)
        current = self.report.get("region", {}).get("country", "DE")
        selected = countries.index(current) if current in countries else 0
        search = ""
        while True:
            h, w = screen.getmaxyx()
            if h < 18 or w < 52:
                return None
            height, width = min(h - 4, 21), min(w - 4, 65)
            dialog = c.newwin(height, width, (h - height) // 2, (w - width) // 2)
            dialog.keypad(True)
            dialog.box()
            self.paint(dialog, 1, 2, "Выбор региона", attr=c.A_BOLD)
            self.paint(dialog, 2, 2, "Код страны: " + (search or "введи DE, NL…"))
            count = height - 7
            start = max(0, min(selected - count // 2, len(countries) - count))
            for index in range(start, min(len(countries), start + count)):
                code = countries[index]
                tz, loc, language = REGIONS[code]
                text = f" {code}   {language:<7}  {tz}"
                self.paint(dialog, 4 + index - start, 2, text.ljust(width - 5), width - 5, c.A_REVERSE if index == selected else 0)
            self.paint(dialog, height - 2, 2, "↑↓ выбор   Enter применить   Esc отмена", width - 4)
            dialog.refresh()
            key = dialog.getch()
            if key == 27:
                return None
            if key in (10, 13, c.KEY_ENTER):
                return countries[selected]
            if key == c.KEY_UP:
                selected = (selected - 1) % len(countries)
            elif key in (c.KEY_DOWN, 9):
                selected = (selected + 1) % len(countries)
            elif key == c.KEY_PPAGE:
                selected = max(0, selected - count)
            elif key == c.KEY_NPAGE:
                selected = min(len(countries) - 1, selected + count)
            elif key in (c.KEY_BACKSPACE, 127, 8):
                search = search[:-1]
            elif 65 <= key <= 90 or 97 <= key <= 122:
                search = (search + chr(key).upper())[-2:]
                matches = [i for i, code in enumerate(countries) if code.startswith(search)]
                if matches:
                    selected = matches[0]

    def confirm(self, screen, title, explanation, action):
        c = self.curses
        accept = False
        while True:
            h, w = screen.getmaxyx()
            if h < 18 or w < 52:
                return False
            width = min(68, w - 4)
            lines = self.wrapped([explanation], width - 6)
            height = len(lines) + 7
            dialog = c.newwin(height, width, (h - height) // 2, (w - width) // 2)
            dialog.keypad(True)
            dialog.box()
            self.paint(dialog, 1, 3, title, width - 6, c.A_BOLD)
            for i, line in enumerate(lines):
                self.paint(dialog, 3 + i, 3, line, width - 6)
            y = height - 2
            self.paint(dialog, y, 3, " Отмена ", attr=c.A_REVERSE if not accept else 0)
            self.paint(dialog, y, 15, " " + action + " ", width - 18, c.A_REVERSE | c.A_BOLD if accept else 0)
            dialog.refresh()
            key = dialog.getch()
            if key == 27:
                return False
            if key in (10, 13, c.KEY_ENTER):
                return accept
            if key in (c.KEY_LEFT, c.KEY_RIGHT, 9):
                accept = not accept

    def activate(self, screen):
        if self.job:
            self.message = "Дождись завершения текущего действия."
            return
        choice = self.selected
        country = None
        if choice == 3:
            country = self.choose_country(screen)
            if not country:
                self.message = "Выбор региона отменён."
                return
        elif choice in (5, 6):
            title, explanation = self.ACTIONS[choice]
            if not self.confirm(screen, title, explanation, "Создать профиль" if choice == 5 else "Выполнить откат"):
                self.message = "Действие отменено."
                return
        self.failed = False
        self.last_action = None
        self.details = self.ip_details = False
        self.job_choice = choice
        self.message = "Выполняется: " + self.ACTIONS[choice][0].lower() + "…"
        self.outputs[choice] = [self.message, "", "Результат появится здесь. Дождись завершения."]
        self.scroll = 0
        self.draw(screen)

        def work():
            out = io.StringIO()
            failed = False
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    if choice == 0:
                        self.manager.show_status()
                    elif choice == 1:
                        self.cache = self.manager.ip()
                        show_ip(self.cache, details=self.ip_details)
                    elif choice in (2, 3):
                        self.manager.apply(auto=choice == 2, country=country,
                                           import_current=bool(not self.manager.state() and self.manager.legacy()))
                    elif choice == 4:
                        self.manager.apply(repair=True)
                    elif choice == 5:
                        old = self.manager.state()
                        self.manager.apply(auto=old["auto_ip"] if old else True,
                                           country=old["region"]["country"] if old else None, rotate=True)
                    elif choice == 6:
                        self.manager.restore()
            except Exception as e:
                failed = True
                out.write("Ошибка: " + clean(e) + "\n")
            self.completed = (choice, out.getvalue().splitlines(), failed)

        self.completed = None
        self.job = threading.Thread(target=work, daemon=True)
        self.job.start()

    def main(self, screen, curses_module):
        self.curses = c = curses_module
        screen.keypad(True)
        screen.timeout(100)
        with contextlib.suppress(c.error):
            c.curs_set(0)
        self.good = self.bad = self.warn = self.accent = 0
        if c.has_colors() and "NO_COLOR" not in os.environ:
            with contextlib.suppress(c.error):
                c.start_color()
                c.use_default_colors()
                # Extended palette avoids themes that map all ANSI colours to similar hues.
                colours = (114, 217, 222, 117) if c.COLORS >= 256 else (c.COLOR_GREEN, c.COLOR_RED, c.COLOR_YELLOW, c.COLOR_CYAN)
                background = os.environ.get("COLORFGBG", "").split(";")[-1]
                if c.COLORS >= 256 and background.isdigit() and int(background) in (7, 15):
                    colours = (22, 124, 94, 24)
                for pair, colour in enumerate(colours, 1):
                    c.init_pair(pair, colour, -1)
                self.good, self.bad, self.warn, self.accent = (c.color_pair(i) for i in (1, 2, 3, 4))
        while True:
            if self.completed is not None:
                choice, lines, self.failed = self.completed
                self.job.join()
                self.job = None
                self.completed = None
                self.last_action = choice
                self.refresh_state()
                self.selected = choice
                self.scroll = 0
                if choice != 0 or self.failed:
                    self.outputs[choice] = lines
                self.message = "Ошибка. Enter: повторить · d: подробности" if self.failed else "Готово. Следующий шаг указан в результате."
            self.draw(screen)
            key = screen.getch()
            if key in (ord("q"), ord("Q"), 27):
                if not self.job:
                    return
                self.message = "Дождись завершения действия перед выходом."
            elif key in (c.KEY_UP, ord("k"), c.KEY_BTAB):
                self.selected = (self.selected - 1) % len(self.ACTIONS)
                self.scroll = 0
                self.details = self.ip_details = False
            elif key in (c.KEY_DOWN, ord("j"), 9):
                self.selected = (self.selected + 1) % len(self.ACTIONS)
                self.scroll = 0
                self.details = self.ip_details = False
            elif ord("1") <= key <= ord("7"):
                self.selected = key - ord("1")
                self.scroll = 0
                self.details = self.ip_details = False
            elif key in (10, 13, c.KEY_ENTER):
                if screen.getmaxyx()[0] >= 18 and screen.getmaxyx()[1] >= 52:
                    self.activate(screen)
            elif key == c.KEY_NPAGE:
                self.scroll += 5
            elif key == c.KEY_PPAGE:
                self.scroll = max(0, self.scroll - 5)
            elif key in (ord("d"), ord("D")) and not self.job:
                if self.selected == 1:
                    self.ip_details = not self.ip_details
                    if self.cache:
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            show_ip(self.cache, details=True)
                        self.outputs[1] = ["Сохранённый результат проверки", ""] + out.getvalue().splitlines()
                else:
                    self.details = not self.details
                self.scroll = 0


def menu(manager, plain=False):
    if plain or os.environ.get("TERM") in (None, "", "dumb"):
        plain_menu(manager)
        return
    try:
        import curses
    except ImportError:
        plain_menu(manager)
        return
    try:
        curses.wrapper(lambda screen: TerminalUI(manager).main(screen, curses))
    except curses.error:
        print("Полноэкранный режим недоступен. Открываю текстовое меню.")
        plain_menu(manager)


def main():
    if not sys.platform.startswith("linux"):
        raise Error("Эта версия поддерживает Linux. Windows и macOS требуют других способов хранения профилей.")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise Error("Запускай без sudo, от своего пользователя")
    args = parser().parse_args()
    manager = Manager(args.config)
    if args.action is None:
        if sys.stdin.isatty():
            menu(manager, args.plain)
        else:
            manager.show_status()
    elif args.action == "status":
        manager.show_status(args.json)
    elif args.action == "ip":
        show_ip(manager.ip(args.provider), details=args.details)
    elif args.action in ("apply", "repair", "rotate"):
        manager.apply(auto=not bool(args.country), country=args.country, cli=args.cli_bin,
                      desktop=args.desktop_bin, import_current=args.import_current,
                      rotate=args.action == "rotate", repair=args.action == "repair", force=args.force)
    elif args.action == "restore":
        manager.restore(args.force)
    elif args.action == "run":
        manager.run(args.kind, args.arguments)


if __name__ == "__main__":
    try:
        main()
    except (Error, OSError) as e:
        print("Ошибка: " + clean(e), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nВыход.")
