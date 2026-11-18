#!/usr/bin/env python3
"""Windows: separate local Claude profiles, region settings, and public IP diagnostics.

Python 3.9+. Fully adapted for Windows (with cross-platform support).
Does not impersonate identities, change hardware IDs, or estimate Anthropic's private anti-abuse decisions.
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

if sys.platform == "win32":
    import msvcrt
    try:
        import winreg
    except ImportError:
        winreg = None
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
else:
    import fcntl
    winreg = None


def setup_windows_console():
    """Initializes Windows console title and enables ANSI Virtual Terminal Processing."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW("AntiSuspended - Claude Profile Manager (Windows)")
        STD_OUTPUT_HANDLE = -11
        handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_ulong()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass


def is_admin():
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_privileges():
    if os.environ.get("CPM_NO_ELEVATE") or sys.platform != "win32" or is_admin():
        return
    if any(h in sys.argv for h in ("-h", "--help")):
        return
    import ctypes
    exe = sys.executable if getattr(sys, "frozen", False) else sys.executable
    if getattr(sys, "frozen", False):
        args = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        args = f'"{Path(__file__).resolve()}" ' + " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    if ret > 32:
        sys.exit(0)
    else:
        print("Ошибка: Для работы требуются права администратора (UAC запрос отклонён).", file=sys.stderr)
        sys.exit(1)

VERSION = "1.2.0-win"
MARKER = ":: claude-profile-manager v1"
AUTH_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_SESSION_ACCESS_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR")

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
        return json.loads(path.read_text(encoding="utf-8"))
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
            if sys.platform != "win32":
                os.fchmod(f.fileno(), mode)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                os.chmod(path, mode)
    finally:
        if os.path.exists(name):
            with contextlib.suppress(OSError):
                os.unlink(name)


def save_json(path, data):
    write_file(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def private_dir(path):
    if path.is_symlink():
        raise Error(f"Каталог профиля не должен быть ссылкой: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            path.chmod(0o700)


def valid_timezone(value):
    if not isinstance(value, str) or len(value) > 100 or not value:
        return False
    try:
        ZoneInfo(value)
        return True
    except (ZoneInfoNotFoundError, ValueError, Exception):
        known_tzs = {tz for tz, _, _ in REGIONS.values()}
        if value in known_tzs or value in ("UTC", "GMT"):
            return True
        return bool(re.fullmatch(r"[A-Za-z_]+(/[A-Za-z_]+)+", value))


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


def check_claude_connectivity():
    """Tests latency and Cloudflare/HTTP response to claude.ai and api.anthropic.com."""
    targets = [
        ("Claude Web (claude.ai)", "https://claude.ai"),
        ("Claude API (api.anthropic.com)", "https://api.anthropic.com")
    ]
    results = []
    for name, url in targets:
        t0 = time.time()
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                ms = int((time.time() - t0) * 1000)
                results.append({"name": name, "ok": True, "ms": ms, "status": resp.status, "note": "Доступен напрямую"})
        except urllib.error.HTTPError as e:
            ms = int((time.time() - t0) * 1000)
            if e.code == 403:
                results.append({"name": name, "ok": False, "ms": ms, "status": 403,
                                "note": "Блокировка Cloudflare (403)! IP или VPN заблокирован Claude."})
            elif e.code == 404 and "api" in url:
                results.append({"name": name, "ok": True, "ms": ms, "status": 200,
                                "note": "API доступен (сервер отвечает)"})
            else:
                results.append({"name": name, "ok": False, "ms": ms, "status": e.code,
                                "note": f"Код ответа HTTP {e.code}"})
        except Exception as e:
            results.append({"name": name, "ok": False, "ms": None, "status": 0,
                            "note": f"Ошибка соединения: {type(e).__name__}"})
    return results


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
        raise Error(f"{provider}: проверка недоступна ({type(e).__name__})") from None


def update_windows_user_path(bin_dir):
    """Safely adds bin_dir to HKCU\\Environment\\Path if not present and broadcasts change."""
    if sys.platform != "win32" or winreg is None:
        return False
    bin_str = str(bin_dir)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError:
        return False
    try:
        try:
            current_path, reg_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current_path, reg_type = "", winreg.REG_EXPAND_SZ
        parts = [p.strip() for p in current_path.split(";") if p.strip()]
        normalized = [os.path.normpath(p).lower() for p in parts]
        if os.path.normpath(bin_str).lower() not in normalized:
            new_path = current_path + (";" if current_path and not current_path.endswith(";") else "") + bin_str
            winreg.SetValueEx(key, "Path", 0, reg_type, new_path)
            # Broadcast environment update to other windows
            try:
                import ctypes
                HWND_BROADCAST = 0xFFFF
                WM_SETTINGCHANGE = 0x001A
                SMTO_ABORTIFHUNG = 0x0002
                result = ctypes.c_long()
                ctypes.windll.user32.SendMessageTimeoutW(
                    HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
                    SMTO_ABORTIFHUNG, 3000, ctypes.byref(result)
                )
            except Exception:
                pass
            return True
        return True
    finally:
        winreg.CloseKey(key)


def create_windows_shortcut(target, shortcut_path, description="Claude (Isolated)", args="", icon=""):
    """Creates a Windows .lnk shortcut using PowerShell."""
    if sys.platform != "win32":
        return
    shortcut_path = Path(shortcut_path)
    shortcut_path.parent.mkdir(parents=True, exist_ok=True)
    ps = (
        f'$w = New-Object -ComObject WScript.Shell; '
        f'$s = $w.CreateShortcut("{shortcut_path}"); '
        f'$s.TargetPath = "{target}"; '
        f'$s.Arguments = "{args}"; '
        f'$s.Description = "{description}"; '
        + (f'$s.IconLocation = "{icon}"; ' if icon else "")
        + '$s.Save()'
    )
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                   capture_output=True, timeout=10)


class Manager:
    def __init__(self, config=None, home=None):
        self.home = Path(home) if home else Path.home()
        if sys.platform == "win32" and not home:
            appdata = os.environ.get("APPDATA") or str(self.home / "AppData" / "Roaming")
            localappdata = os.environ.get("LOCALAPPDATA") or str(self.home / "AppData" / "Local")
            self.config = (Path(config) if config else Path(appdata) / "claude-profile-manager").expanduser().absolute()
            self.data = Path(localappdata) / "claude-profile-manager"
            self.bin = self.data / "bin"
            self.apps = self.data / "shortcuts"
        else:
            self.config = (Path(config) if config else Path(os.environ.get("XDG_CONFIG_HOME", self.home / ".config")) / "claude-profile-manager").expanduser().absolute()
            self.data = (self.home / ".local/share" if home else Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share"))) / "claude-profile-manager"
            self.bin = self.home / ".local/bin"
            self.apps = (self.home / ".local/share" if home else Path(os.environ.get("XDG_DATA_HOME", self.home / ".local/share"))) / "applications"

        self.statefile = self.config / "state.json"
        self.cachefile = self.config / "last-ip.json"

    @contextlib.contextmanager
    def lock(self):
        private_dir(self.config)
        lock_file = self.config / "lock"
        if sys.platform == "win32":
            f = lock_file.open("a+b")
            try:
                f.seek(0)
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                except (OSError, IOError):
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                yield
            finally:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except (OSError, IOError):
                    pass
                f.close()
        else:
            with lock_file.open("a") as f:
                os.chmod(f.name, 0o600)
                fcntl.flock(f, fcntl.LOCK_EX)
                yield

    def state(self):
        data = read_json(self.statefile)
        if data is not None and (not isinstance(data, dict) or data.get("schema") != 1):
            raise Error("Неизвестный формат настроек; запись остановлена")
        return data

    def kill_hung_claude(self, verbose=True):
        """Terminates any background stuck/hung Claude processes to prevent singleton lock errors."""
        if sys.platform == "win32":
            subprocess.run(["cmd.exe", "/c", "taskkill /f /im claude.exe /im claude-desktop.exe 2>nul"], capture_output=True)
            if verbose:
                print("Фоновые зависшие процессы Claude завершены.")

    def ensure_icon_persisted(self):
        """Persists app_icon.ico into self.data for system shortcuts."""
        target = self.data / "app_icon.ico"
        if target.is_file():
            return target
        candidates = []
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            candidates.append(Path(sys._MEIPASS) / "app_icon.ico")
        candidates.append(Path(__file__).resolve().parent / "app_icon.ico")
        for c in candidates:
            if c.is_file():
                with contextlib.suppress(Exception):
                    self.data.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(c, target)
                    return target
        return None

    def create_manager_shortcut(self):
        """Creates a desktop shortcut for AntiSuspended with icon and admin rights."""
        if sys.platform != "win32":
            return
        user_desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
        if not user_desktop.is_dir():
            raise Error("Рабочий стол пользователя не найден.")
        shortcut_path = user_desktop / "AntiSuspended.lnk"
        exe_path = sys.executable if getattr(sys, "frozen", False) else sys.executable
        args = "" if getattr(sys, "frozen", False) else f'"{Path(__file__).resolve()}"'
        icon_path = ""
        possible_icons = [
            self.ensure_icon_persisted(),
            self.data / "app_icon.ico",
            Path(__file__).resolve().parent / "app_icon.ico",
            Path(sys.executable).resolve()
        ]
        for p in possible_icons:
            if p and Path(p).is_file():
                icon_path = str(p)
                break
        create_windows_shortcut(
            target=str(exe_path),
            shortcut_path=str(shortcut_path),
            description="AntiSuspended - Claude Profile Manager (Windows)",
            args=args,
            icon=f"{icon_path},0" if icon_path else ""
        )
        print(f"Ярлык AntiSuspended успешно создан на Рабочем столе: {shortcut_path}")

    def executable(self, kind, explicit=None):
        if explicit:
            p = Path(explicit).expanduser().absolute()
            if p.parent == self.bin and not p.is_symlink():
                raise Error("Укажи исходную программу, а не создаваемую обёртку")
            if not p.is_file() or (sys.platform != "win32" and not os.access(p, os.X_OK)):
                raise Error("Исходная программа не найдена или не исполняемая: " + str(p))
            return str(p.resolve()) if p.is_symlink() else str(p)

        candidates = []
        if sys.platform == "win32":
            localappdata = Path(os.environ.get("LOCALAPPDATA", ""))
            appdata = Path(os.environ.get("APPDATA", ""))
            progfiles = Path(os.environ.get("ProgramFiles", "C:\\Program Files"))
            progfiles_x86 = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"))

            if kind == "desktop":
                # Primary: Windows 11 App Execution Alias for Claude MSIX package
                candidates.append(localappdata / "Microsoft" / "WindowsApps" / "claude-desktop.exe")
                candidates.append(localappdata / "Microsoft" / "WindowsApps" / "Claude_pzs8sxrjxfjjc" / "claude-desktop.exe")
                # Secondary: WindowsApps package directories
                try:
                    for p_dir in Path(r"C:\Program Files\WindowsApps").glob("Claude_*"):
                        candidates.append(p_dir / "app" / "Claude.exe")
                except Exception:
                    pass
                # Tertiary: Standard Anthropic installer locations
                candidates.append(localappdata / "AnthropicClaude" / "Claude.exe")
                candidates.append(localappdata / "Programs" / "Claude" / "Claude.exe")
                candidates.append(progfiles / "Claude" / "Claude.exe")
                candidates.append(progfiles_x86 / "Claude" / "Claude.exe")
                # Look in PATH strictly for claude-desktop (never generic claude.exe!)
                for d in os.get_exec_path():
                    if d and Path(d).resolve() != self.bin.resolve():
                        for n in ("claude-desktop.exe", "claude-desktop.cmd"):
                            candidates.append(Path(d) / n)
            else:
                # CLI locations
                userprofile = Path(os.environ.get("USERPROFILE", ""))
                candidates.append(userprofile / ".local" / "bin" / "claude.exe")
                candidates.append(appdata / "npm" / "claude.cmd")
                candidates.append(appdata / "npm" / "claude.ps1")
                candidates.append(localappdata / "Programs" / "ClaudeCode" / "claude.exe")
                for d in os.get_exec_path():
                    if d and Path(d).resolve() != self.bin.resolve():
                        for n in ("claude.cmd", "claude.exe", "claude.bat", "claude.ps1"):
                            candidates.append(Path(d) / n)
        else:
            name = "claude" if kind == "cli" else "claude-desktop"
            candidates += [Path("/usr/bin") / name, Path("/usr/local/bin") / name]
            for d in os.get_exec_path():
                if d and Path(d).resolve() != self.bin.resolve():
                    candidates.append(Path(d) / name)

        for p in candidates:
            if p.resolve() == (self.bin / p.name).resolve():
                if p.is_symlink() and p.resolve().is_file() and os.access(p, os.X_OK):
                    return str(p.resolve())
                continue
            if p.is_file() and (sys.platform == "win32" or os.access(p, os.X_OK)):
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

    def list_profiles(self):
        """Lists all existing profiles in profiles directory with metadata."""
        prof_dir = self.data / "profiles"
        if not prof_dir.is_dir():
            return []
        current_state = self.state()
        active_root = current_state["profile"]["root"] if current_state else None
        results = []
        for p in sorted(prof_dir.iterdir(), reverse=True):
            if p.is_dir():
                is_active = (str(p.resolve()) == str(Path(active_root).resolve())) if active_root else False
                auth_file = p / "code" / ".credentials.json"
                claude_json = p / "code" / ".claude.json"
                has_auth = auth_file.is_file() or claude_json.is_file()
                mtime = p.stat().st_mtime
                date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
                results.append({
                    "name": p.name,
                    "root": str(p),
                    "code": str(p / "code"),
                    "desktop_config": str(p / "desktop-config"),
                    "cache": str(p / "cache"),
                    "state": str(p / "state"),
                    "active": is_active,
                    "date": date_str,
                    "has_auth": has_auth
                })
        return results

    def switch_profile(self, target_identifier):
        """Switches active profile to a chosen profile by name, index (1-based), or path."""
        with self.lock():
            state = self.state()
            if not state:
                raise Error("Сначала выполни apply для первичной настройки")
            profiles = self.list_profiles()
            match = None
            if str(target_identifier).isdigit():
                idx = int(target_identifier) - 1
                if 0 <= idx < len(profiles):
                    match = profiles[idx]
            if not match:
                for prof in profiles:
                    if prof["name"] == target_identifier or prof["root"] == target_identifier:
                        match = prof
                        break
            if not match:
                raise Error(f"Профиль '{target_identifier}' не найден")

            old_prof = state["profile"]
            new_prof = {
                "root": match["root"],
                "code": match["code"],
                "desktop_config": match["desktop_config"],
                "cache": match["cache"],
                "state": match["state"]
            }
            if str(new_prof["root"]) == str(old_prof["root"]):
                print(f"Профиль {match['name']} уже активен.")
                return match

            prevs = state.get("previous_profiles", [])
            if old_prof not in prevs:
                prevs.append(old_prof)
            state["previous_profiles"] = prevs
            state["profile"] = new_prof
            self.ensure_profile(new_prof)
            save_json(self.statefile, state)
            print(f"Активный профиль переключен на: {match['name']} ({match['date']})")
            return match

    def launch_client(self, kind):
        """Directly launches Claude Desktop or Claude Code with active profile settings."""
        state = self.state()
        if not state:
            raise Error("Сначала примените настройку (выберите пункт 'Авто-настройка по IP')")
        exe = state["executables"].get(kind)
        if not exe or not Path(exe).is_file():
            if kind == "desktop":
                raise Error("Claude Desktop не найден на компьютере. Скачайте его с https://claude.ai/download")
            else:
                raise Error("Claude Code CLI не найден. Установите его: npm install -g @anthropic-ai/claude-code")
        if kind == "desktop":
            self.kill_hung_claude(verbose=False)
            return self.run("desktop", [])
        else:
            if sys.platform == "win32":
                # Launch in new command prompt window so it doesn't block the manager
                runner = self.manager_runner()
                cmd = f'start "Claude Code" cmd /k ""{runner[0]}" run cli"'
                subprocess.Popen(cmd, shell=True)
                print("Claude Code запущен в новом окне терминала.")
            else:
                return self.run("cli", [])

    def manager_runner(self):
        """Returns the command tokens used to invoke this manager."""
        if getattr(sys, "frozen", False):
            # Running as a compiled PyInstaller executable
            return [str(Path(sys.executable).resolve())]
        target = self.config / "manager.py"
        return [sys.executable, str(target), "--config", str(self.config)]

    def plan(self, state):
        plan = {}
        runner = self.manager_runner()

        if sys.platform == "win32":
            # 1. Main manager wrapper for Windows
            mgr_target = runner[0]
            mgr_extra = " ".join(f'"{arg}"' for arg in runner[1:])
            mgr_cmd = (
                f"@echo off\r\n{MARKER}\r\n"
                f'"{mgr_target}" {mgr_extra} %*\r\n'
            )
            plan[self.bin / "claude-profile-manager.cmd"] = (mgr_cmd.encode("utf-8"), 0o755)

            # 2. CLI wrapper
            if state["executables"].get("cli"):
                cli_cmd = (
                    f"@echo off\r\n{MARKER}\r\n"
                    f'"{mgr_target}" {mgr_extra} run cli %*\r\n'
                )
                plan[self.bin / "claude.cmd"] = (cli_cmd.encode("utf-8"), 0o755)

            # 3. Desktop wrapper
            if state["executables"].get("desktop"):
                desk_cmd = (
                    f"@echo off\r\n{MARKER}\r\n"
                    f'start "" "{mgr_target}" {mgr_extra} run desktop %*\r\n'
                )
                plan[self.bin / "claude-desktop.cmd"] = (desk_cmd.encode("utf-8"), 0o755)

        else:
            # POSIX Linux / macOS
            manager_command = "#!/bin/sh\n" + MARKER + "\nexec " + shlex.join(runner) + ' "$@"\n'
            plan[self.bin / "claude-profile-manager"] = (manager_command.encode(), 0o755)
            if state["executables"].get("cli"):
                cli_launcher = "#!/bin/sh\n" + MARKER + "\nexec " + shlex.join(runner + ["run", "cli"]) + ' "$@"\n'
                plan[self.bin / "claude"] = (cli_launcher.encode(), 0o755)
                handler = ("[Desktop Entry]\nName=Claude Code URL Handler\nType=Application\nNoDisplay=true\n"
                           f'Exec="{self.bin / "claude"}" --handle-uri %u\nMimeType=x-scheme-handler/claude-cli;\n')
                plan[self.apps / "claude-code-url-handler.desktop"] = (handler.encode(), 0o644)
            if state["executables"].get("desktop"):
                desk_launcher = "#!/bin/sh\n" + MARKER + "\nexec " + shlex.join(runner + ["run", "desktop"]) + ' "$@"\n'
                plan[self.bin / "claude-desktop"] = (desk_launcher.encode(), 0o755)
                desk_entry = (
                    "[Desktop Entry]\nName=Claude\nType=Application\n"
                    f'Exec="{self.bin / "claude-desktop"}" %U\nIcon=claude-desktop\n'
                    "Categories=Development;\nMimeType=x-scheme-handler/claude;\n"
                )
                plan[self.apps / "claude-profile.desktop"] = (desk_entry.encode(), 0o644)

        return plan

    def locale_env(self, state, selected):
        environment = os.environ.copy()
        environment.pop("IPAPI_IS_KEY", None)
        desired = selected["locale"]
        available = True

        if sys.platform != "win32":
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
                    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                        result = subprocess.run(["localedef", "--no-archive", "-i", desired.split(".")[0], "-f", "UTF-8", str(target)], capture_output=True, timeout=30)
                        if result.returncode:
                            shutil.rmtree(target, ignore_errors=True)
                if (target / "LC_CTYPE").exists():
                    probe["LOCPATH"] = str(directory)
                    result = subprocess.run(["locale", "charmap"], env=probe, capture_output=True, timeout=5) if shutil.which("locale") else None
                    available = bool(result and result.returncode == 0 and not result.stderr and b"UTF-8" in result.stdout)
                    if available:
                        environment["LOCPATH"] = str(directory)
            chosen = desired if available else "C.UTF-8"
            environment.update(LANG=chosen, LC_ALL=chosen,
                               LANGUAGE=selected["language"].replace("-", "_") + ":" + selected["language"].split("-")[0])

        environment.update(TZ=selected["timezone"],
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
            for p, (content, mode) in plan.items():
                record = state["files"].get(str(p))
                allowed_link = p.is_symlink() and p.parent == self.bin and str(p.resolve()) in executables.values()
                if (p.is_symlink() and not allowed_link) or (p.exists() and not p.is_file()):
                    raise Error("Не заменяю ссылку или специальный файл: " + str(p))
                if record and p.exists() and digest(p.read_bytes()) != record["installed"] and not force:
                    raise Error("Файл изменён извне: " + str(p) + ". Для осознанной замены: repair --force")

            private_dir(self.config / "backups")
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
            if not getattr(sys, "frozen", False):
                runtime = Path(__file__).read_bytes()
                write_file(self.config / "manager.py", runtime, 0o700)
                state["runtime_sha256"] = digest(runtime)
            else:
                exe_bytes = Path(sys.executable).read_bytes()
                state["runtime_sha256"] = digest(exe_bytes)

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

            # Ensure Windows PATH has our bin directory
            if sys.platform == "win32":
                update_windows_user_path(self.bin)
                self.ensure_icon_persisted()
                # Create a Start Menu / Desktop shortcut for Claude Desktop if available
                if state["executables"].get("desktop"):
                    with contextlib.suppress(Exception):
                        desk_target = str(self.bin / "claude-desktop.cmd")
                        user_desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
                        if user_desktop.is_dir():
                            create_windows_shortcut(desk_target, user_desktop / "Claude (Isolated).lnk",
                                                    description="Claude Desktop (Isolated Profile)",
                                                    icon=state["executables"]["desktop"])
                with contextlib.suppress(Exception):
                    self.create_manager_shortcut()

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
                    write_file(p, (self.config / "backups" / record["backup"]).read_bytes(), record.get("before_mode") or 0o644)
                elif p.exists():
                    p.unlink()

            # Remove Desktop shortcuts on Windows if created
            if sys.platform == "win32":
                for lnk_name in ("Claude (Isolated).lnk", "AntiSuspended.lnk"):
                    desk_lnk = Path(os.environ.get("USERPROFILE", "")) / "Desktop" / lnk_name
                    if desk_lnk.is_file():
                        with contextlib.suppress(OSError):
                            desk_lnk.unlink()

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

        cli_exe = state["executables"].get("cli")
        desk_exe = state["executables"].get("desktop")
        add("CLI: найден исходный исполняемый файл", not cli_exe or Path(cli_exe).is_file())
        add("Desktop: найден исходный исполняемый файл", not desk_exe or Path(desk_exe).is_file())

        shared_links = [Path(profile["code"]) / name for name in (".claude.json", ".credentials.json")]
        shared_links += [Path(profile["desktop_config"]) / "Claude" / name for name in ("Cookies", "Local Storage", "Session Storage", "IndexedDB", "Partitions")]
        shared_links += [Path(profile["desktop_config"]) / "Claude"]

        # Default paths on Windows vs POSIX
        if sys.platform == "win32":
            std_code = (self.home / ".claude").absolute()
            std_desk = (Path(os.environ.get("APPDATA", "")) / "Claude").absolute()
        else:
            std_code = (self.home / ".claude").absolute()
            std_desk = (self.home / ".config").absolute()

        add("Каталоги профиля отделены от стандартных",
            Path(profile["code"]).absolute() != std_code and
            Path(profile["desktop_config"]).absolute() != std_desk and
            not any(p.is_symlink() for p in shared_links))

        # Check directory permissions / accessibility
        dirs_ok = True
        for v in set(profile.values()):
            p = Path(v)
            if not p.is_dir() or p.is_symlink():
                dirs_ok = False
                break
            if sys.platform != "win32":
                if stat.S_IMODE(p.stat().st_mode) & 0o077 != 0:
                    dirs_ok = False
                    break
            else:
                # Test write access
                test_f = p / ".cpm_test"
                try:
                    test_f.write_text("ok")
                    test_f.unlink()
                except OSError:
                    dirs_ok = False
                    break
        add("Каталоги профиля закрыты для других пользователей", dirs_ok)

        # Check wrappers and PATH
        path_execs = [("cli", "claude.cmd" if sys.platform == "win32" else "claude"),
                      ("desktop", "claude-desktop.cmd" if sys.platform == "win32" else "claude-desktop")]
        wrappers_ok = all(intact(Path(p)) for p in records if Path(p).parent == self.bin)
        which_ok = True
        for kind, name in path_execs:
            if state["executables"].get(kind):
                found = shutil.which(name)
                # Either found in our bin or directly points to our bin
                if not found or Path(found).resolve() != (self.bin / name).resolve():
                    # Check if our bin is in PATH
                    if str(self.bin).lower() not in os.environ.get("PATH", "").lower():
                        which_ok = False
        add("Команды клиентов направлены в менеджер и доступны через PATH", wrappers_ok and which_ok)

        # Shortcuts / .desktop files
        if sys.platform == "win32":
            desk_ok = all(intact(Path(p)) for p in records if p.endswith(".cmd"))
        else:
            desk_ok = all(intact(Path(p)) for p in records if p.endswith(".desktop"))
        add("Ярлыки и обработчик ссылок не изменены извне", desk_ok)

        add("Сохранён допустимый часовой пояс", valid_timezone(state["region"].get("timezone")))
        add("Доступна выбранная системная локаль", state.get("locale_available") is True)
        add("В окружении не заданы явные токены входа", not any(os.environ.get(k) for k in AUTH_ENV))

        if getattr(sys, "frozen", False):
            runtime_ok = True
        else:
            runtime = self.config / "manager.py"
            runtime_ok = runtime.is_file() and digest(runtime.read_bytes()) == state.get("runtime_sha256")
        backups_ok = all(not r.get("pending") and (not r["backup"] or (self.config / "backups" / r["backup"]).is_file()) for r in records.values())
        add("Резервные копии доступны, установка завершена", backups_ok and runtime_ok)

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
        result["claude_probes"] = check_claude_connectivity()
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
        if not Path(executable).is_file():
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

        print(f"Claude {kind}: {selected['country']}, {selected['timezone']}, {selected['language']}", file=sys.stderr)

        if kind == "desktop":
            p = state["profile"]
            # Electron arguments for isolated profile & language
            electron_args = [
                f"--user-data-dir={p['desktop_config']}",
                f"--lang={selected['language']}"
            ]
            if sys.platform != "win32":
                environment.update(XDG_CONFIG_HOME=p["desktop_config"], XDG_CACHE_HOME=p["cache"], XDG_STATE_HOME=p["state"])
            full_cmd = [executable] + electron_args + arguments
            if sys.platform == "win32":
                proc = subprocess.Popen(full_cmd, env=environment)
                return proc
            else:
                os.umask(0o077)
                os.execve(executable, full_cmd, environment)
        else:
            # CLI mode
            full_cmd = [executable] + arguments
            if sys.platform == "win32":
                is_batch = executable.lower().endswith((".cmd", ".bat"))
                try:
                    proc = subprocess.run(full_cmd, env=environment, shell=is_batch)
                    sys.exit(proc.returncode)
                except KeyboardInterrupt:
                    sys.exit(130)
            else:
                os.umask(0o077)
                os.execve(executable, full_cmd, environment)


def show_ip(result, details=False, check_claude=True):
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

    if check_claude:
        print("\n--- Доступность Claude с текущего подключения ---")
        probes = result.get("claude_probes") or check_claude_connectivity()
        for probe in probes:
            tag = "[OK]" if probe["ok"] else "[!!]"
            latency = f"({probe['ms']} ms)" if probe.get("ms") is not None else ""
            print(f"{tag} {probe['name']}: {probe['note']} {latency}")


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
    p = argparse.ArgumentParser(description="Отдельные профили Claude для Windows и Linux; проверка настроек и выходного IP.")
    p.add_argument("--config", type=Path, help="Каталог настроек менеджера")
    p.add_argument("--plain", action="store_true", help="Текстовое меню для простых терминалов и скринридеров")
    sub = p.add_subparsers(dest="action")
    status = sub.add_parser("status", help="Проверить настройки без сетевого запроса")
    status.add_argument("--json", action="store_true")
    ip = sub.add_parser("ip", help="Проверить IP через внешний сервис и доступность Claude")
    ip.add_argument("--provider", choices=["ipquery.io", "ipwho.is", "ipapi.is"], help="Один источник вместо сравнения ipwho.is + ipquery.io; при IPAPI_IS_KEY используется ipapi.is")
    ip.add_argument("--details", action="store_true", help="Показать источники и ограничения проверки")
    ping = sub.add_parser("ping", help="Проверить доступность серверов Claude (claude.ai и API)")
    profiles = sub.add_parser("profiles", help="Показать список всех созданных профилей")
    switch = sub.add_parser("switch", help="Переключить активный профиль")
    switch.add_argument("target", help="Номер (1, 2...) или имя папки профиля")
    launch = sub.add_parser("launch", help="Запустить клиент с изолированным профилем")
    launch.add_argument("kind", choices=["desktop", "cli"], help="desktop или cli")
    kill_cmd = sub.add_parser("kill", help="Снять все зависшие фоновые процессы Claude")
    shortcut_cmd = sub.add_parser("shortcut", help="Создать ярлык AntiSuspended на Рабочем столе")
    for name in ["apply", "repair", "rotate"]:
        cmd = sub.add_parser(name, help={"apply": "Применить настройки", "repair": "Восстановить обёртки, сохранив профиль", "rotate": "Создать новый пустой профиль; старый сохранить"}[name])
        cmd.add_argument("--country", choices=sorted(REGIONS), help="Ручной регион вместо определения по IP")
        cmd.add_argument("--cli-bin", help="Путь к исходному Claude Code")
        cmd.add_argument("--desktop-bin", help="Путь к исходному Claude Desktop")
        cmd.add_argument("--import-current", action="store_true", help="Импортировать прежнюю настройку claude-isolated")
        cmd.add_argument("--force", action="store_true", help="Заменить изменённые извне обёртки")
    restore = sub.add_parser("restore", help="Вернуть прежние команды, сохранив данные профилей")
    restore.add_argument("--force", action="store_true")
    run = sub.add_parser("run", help="Запустить клиент с настройками профиля")
    run.add_argument("kind", choices=["cli", "desktop"])
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    p.add_argument("--version", action="version", version=VERSION)
    return p


BANNER = """
\033[38;2;217;119;87m╔══════════════════════════════════════════════════════════════════════╗
║             🛡️  AntiSuspended - Claude Profile Manager  🛡️           ║
║                    Windows Native Edition v1.2.0                     ║
╚══════════════════════════════════════════════════════════════════════╝\033[0m
"""


def plain_menu(manager):
    while True:
        print("\n" + BANNER.strip())
        print(" 1. Проверить настройки и оценку локальной изоляции (10/10)")
        print(" 2. Проверить выходной IP, сеть и доступность Claude")
        print(" 3. Авто-настройка в 1 клик (выбирать регион по IP)")
        print(" 4. Настройка с ручным выбором страны")
        print(" 5. Запустить Claude Desktop (Изолированный)")
        print(" 6. Запустить Claude Code (CLI)")
        print(" 7. Список и переключение профилей (мультиаккаунт)")
        print(" 8. Создать новый пустой профиль (ротация)")
        print(" 9. Завершить зависшие процессы Claude (taskkill)")
        print("10. Создать ярлык AntiSuspended на Рабочем столе")
        print("11. Восстановить ярлыки и команды")
        print("12. Откатить установку (вернуть прежние команды)")
        print(" 0. Выход")
        try:
            choice = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        try:
            if choice == "0":
                return
            elif choice == "1":
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
                manager.launch_client("desktop")
            elif choice == "6":
                manager.launch_client("cli")
            elif choice == "7":
                profs = manager.list_profiles()
                if not profs:
                    print("Профили ещё не созданы.")
                else:
                    print("\nСписок профилей:")
                    for idx, p in enumerate(profs, 1):
                        act = " [АКТИВЕН]" if p["active"] else ""
                        auth = " [Есть вход]" if p["has_auth"] else " [Чистый]"
                        print(f"  {idx}. {p['name']} ({p['date']}){auth}{act}")
                    sel = input("\nНомер профиля для активации (Enter для отмены): ").strip()
                    if sel:
                        manager.switch_profile(sel)
            elif choice == "8":
                print("Потребуется новый вход. Существующий профиль останется на диске.")
                if input("Создать пустой профиль? [y/N] ").strip().lower() in ("y", "yes", "д", "да"):
                    old = manager.state()
                    manager.apply(auto=old["auto_ip"] if old else True, country=old["region"]["country"] if old else None, rotate=True)
            elif choice == "9":
                manager.kill_hung_claude()
            elif choice == "10":
                manager.create_manager_shortcut()
            elif choice == "11":
                manager.apply(repair=True)
            elif choice == "12":
                if input("Вернуть исходные команды и ярлыки? [y/N] ").strip().lower() in ("y", "yes", "д", "да"):
                    manager.restore()
            else:
                print("Выбери пункт от 0 до 12.")
        except Error as e:
            print("Ошибка: " + clean(e), file=sys.stderr)


def terminal_clip(value, width):
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
        ("Обзор и статус", "Проверить настройки, оценку изоляции (10/10) и активный профиль."),
        ("Проверить сеть и Claude", "Запросить выходной IP, признаки VPN/хостинга и доступность claude.ai."),
        ("Авто-настройка по IP", "Настроить всё в 1 клик: часовой пояс и язык выберутся по текущему IP."),
        ("Задать страну вручную", "Выбрать страну (например, NL, DE, US, GB) без внешних запросов."),
        ("Запустить Claude Desktop", "Открыть изолированный Claude Desktop с текущим профилем."),
        ("Запустить Claude Code", "Запустить Claude Code (CLI) в отдельном окне терминала."),
        ("Сменить профиль", "Выбрать и активировать другой профиль из существующих (мультиакк)."),
        ("Новый пустой профиль", "Создать чистый профиль для нового аккаунта (старый сохранится)."),
        ("Снять процессы Claude", "Принудительно закрыть зависшие процессы Claude при ошибках блокировки."),
        ("Ярлык на Рабочем столе", "Создать ярлык AntiSuspended с иконкой на Рабочем столе."),
        ("Починить ярлыки", "Восстановить команды, ярлык на рабочем столе и регистрацию в PATH."),
        ("Откатить установку", "Вернуть исходные команды и ярлыки без удаления данных профилей."),
    ]
    HINTS = [
        "С чего начать", "IP, пинг, Cloudflare", "Регион по IP", "Выбрать страну",
        "Запустить Desktop", "Запустить CLI", "Список и смена", "Чистый для нового входа",
        "Снять зависшие процессы", "Создать ярлык", "Сбой команд/PATH", "Прежние команды"
    ]
    WHEN = {2: "Для первой настройки или смены региона вслед за VPN.",
            3: "Если хочешь сам выбрать язык и часовой пояс.",
            4: "Запустить Claude Desktop с текущим профилем.",
            5: "Запустить терминальный Claude Code в новом окне.",
            6: "Переключиться на другой сохранённый аккаунт/профиль.",
            7: "Создать пустой профиль для нового аккаунта.",
            8: "Если Claude Desktop не открывается из-за зависшего процесса.",
            9: "Создать ярлык на Рабочем столе с иконкой.",
            10: "Если команда или ярлык запускает Claude неправильно.",
            11: "Если хочешь прекратить использовать менеджер."}
    FIXES = {0: "Проверь установку CLI; затем выбери 9, Enter.",
             1: "Проверь установку Desktop; затем выбери 9, Enter.",
             2: "Проверь каталоги профилей в подробностях (d).",
             3: "Проверь права каталогов профилей в подробностях (d).",
             4: "Выбери 9, Enter. Если не помогло, перезапусти терминал (PATH).",
             5: "Выбери 9, Enter, чтобы восстановить ярлыки.",
             6: "Выбери 3 или 4 и задай регион заново.",
             7: "Проверь региональные настройки и выбери 9, Enter.",
             8: "Убери переменные токенов из окружения этого терминала (список: d).",
             9: "Выбери 9, Enter. При ошибке посмотри подробности (d)."}

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
        if not self.report.get("installed"):
            rows = [("Что делать сейчас", "heading"),
                    ("Выбери 3, затем Enter: настроить всё по текущему IP.", "accent"),
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
                     ("5: Запустить Claude Desktop.", "accent") if self.report.get("clients", {}).get("desktop") else ("Desktop не настроен.", "warn"),
                     ("6: Запустить Claude Code (CLI).", "accent") if self.report.get("clients", {}).get("cli") else ("CLI не настроен.", "warn"),
                     ("2: Проверить сеть и Cloudflare.", "normal")]
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
                    ("Выходной IP, страну, провайдера, отметки VPN/прокси и доступность claude.ai.", "normal"),
                    ("Запрос уйдёт во внешние сервисы определения IP и к Claude.", "normal")]
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
        score = r.get("provider_risk")
        if incomplete:
            rows.append(("Оценка риска: недоступна (неполная запись сети)", "warn"))
        elif score is not None:
            rows.append((f"Риск по базе {r.get('risk_provider', r.get('provider', '?'))}: {score}/100", "warn" if score > 30 else "normal"))

        # Live Claude connectivity probe status
        rows += [("", "normal"), ("Доступность Claude", "heading")]
        probes = r.get("claude_probes") or []
        for p in probes:
            tag = "[OK] " if p["ok"] else "[!!] "
            tone = "good" if p["ok"] else "bad"
            ms = f"({p['ms']} ms)" if p.get("ms") is not None else ""
            rows.append((f"{tag}{p['name']}: {p['note']} {ms}", tone))

        rows += [("", "normal"), ("Границы проверки", "heading"),
                 ("Проверен маршрут к сервису IP и ответ серверов Claude.", "normal"),
                 ("d: источники и технический отчёт", "accent")]
        return rows

    def view(self, choice):
        if choice == 0:
            return self.diagnostics() if self.details else self.overview()
        if choice == 1:
            return self.network_details() if self.ip_details else self.network_view()
        if choice == 4:
            desk_exe = self.report.get("clients", {}).get("desktop")
            rows = [("Запуск Claude Desktop", "heading"), ("", "normal")]
            if desk_exe:
                rows.append(("Клиент найден и настроен.", "good"))
                rows.append(("Нажмите Enter, чтобы открыть изолированный Claude Desktop.", "accent"))
            else:
                rows.append(("Claude Desktop не найден на компьютере.", "bad"))
                rows.append(("Скачайте его с официального сайта: https://claude.ai/download", "warn"))
            return rows
        if choice == 5:
            cli_exe = self.report.get("clients", {}).get("cli")
            rows = [("Запуск Claude Code (CLI)", "heading"), ("", "normal")]
            if cli_exe:
                rows.append(("Клиент найден и настроен.", "good"))
                rows.append(("Нажмите Enter, чтобы запустить в новом окне терминала.", "accent"))
            else:
                rows.append(("Claude Code CLI не найден.", "bad"))
                rows.append(("Установите его через: npm install -g @anthropic-ai/claude-code", "warn"))
            return rows
        if choice == 6:
            profiles = self.manager.list_profiles()
            if not profiles:
                return [("Профили ещё не созданы", "warn"), ("Сначала выберите пункт 3 (Авто-настройка).", "normal")]
            rows = [("Существующие профили (мультиаккаунт)", "heading"), ("", "normal")]
            for idx, p in enumerate(profiles, 1):
                act = " [АКТИВЕН]" if p["active"] else ""
                tone = "good" if p["active"] else "normal"
                auth = " (есть вход)" if p["has_auth"] else " (чистый)"
                rows.append((f"{idx}. {p['name']}{act}", tone))
                rows.append((f"   Создан: {p['date']}{auth}", "normal"))
            rows += [("", "normal"), ("Нажмите Enter, чтобы ввести номер профиля для переключения.", "accent")]
            return rows
        lines = self.outputs.get(choice)
        if lines:
            tag = "bad" if self.failed else "normal"
            return [(line, tag) for line in lines]
        return [(self.ACTIONS[choice][0], "heading"), ("", "normal"),
                ("Нажми Enter, чтобы выполнить.", "accent"), ("", "normal"),
                (self.WHEN.get(choice, ""), "normal"), ("", "normal"),
                ("Пояснение действия", "heading"),
                (self.ACTIONS[choice][1], "normal")]

    def network_details(self):
        r = self.cache
        if not r:
            return [("Нет сохранённых сведений", "warn")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            show_ip_details(r)
        return [(line, "normal") for line in out.getvalue().splitlines()]

    def style(self, screen, text, tone):
        c = self.curses
        attrs = {"heading": c.A_BOLD, "good": self.good, "bad": self.bad,
                 "warn": self.warn, "accent": self.accent}.get(tone, 0)
        return text, attrs

    def draw(self, screen):
        screen.erase()
        h, w = screen.getmaxyx()
        if h < 18 or w < 52:
            warning = "Нужен терминал от 52x18 (сейчас " + str(w) + "x" + str(h) + ")"
            screen.addstr(0, 0, terminal_clip(warning, w - 1))
            screen.refresh()
            return
        c = self.curses
        left_w = min(max(24, w // 3), 32)
        right_w = max(10, w - left_w - 3)

        # Header
        installed = self.report.get("installed")
        score = self.report.get("score")
        summary = "Claude Profile Manager " + VERSION
        if installed:
            tag = f"[{score}/10]"
            screen.addstr(0, 1, terminal_clip(summary, w - len(tag) - 4), c.A_BOLD)
            tone = self.good if self.all_ok() else self.warn if (score or 0) >= 7 else self.bad
            screen.addstr(0, max(1, w - len(tag) - 2), tag, tone | c.A_BOLD)
        else:
            screen.addstr(0, 1, terminal_clip(summary + " [не настроен]", w - 2), c.A_BOLD)

        # Menu items
        compact = h < 26
        for i, (title, desc) in enumerate(self.ACTIONS):
            y = 2 + (i if compact else i * 2)
            if y >= h - 2:
                break
            indicator = "> " if i == self.selected else "  "
            num_label = "0" if i == len(self.ACTIONS) - 1 else str(i + 1)
            line = f"{indicator}{num_label}. {title}"
            attr = c.A_REVERSE if i == self.selected else 0
            screen.addstr(y, 1, terminal_clip(line, left_w), attr)
            if not compact and y + 1 < h - 2:
                hint = self.HINTS[i] if i < len(self.HINTS) else ""
                hint_attr = c.A_DIM if i != self.selected else attr
                screen.addstr(y + 1, 4, terminal_clip(hint, left_w - 4), hint_attr)

        # Vertical divider
        for y in range(1, h - 1):
            with contextlib.suppress(Exception):
                screen.addch(y, left_w + 1, "|")

        # Right pane content
        content = self.view(self.selected)
        visible = content[self.scroll:self.scroll + (h - 3)]
        for idx, (text, tone) in enumerate(visible):
            y = 1 + idx
            if y >= h - 1:
                break
            styled, attr = self.style(screen, text, tone)
            screen.addstr(y, left_w + 3, terminal_clip(styled, right_w), attr)

        # Footer
        footer = self.message
        if self.job and self.job.is_alive():
            footer = "Выполняется запрос, пожалуйста подождите…"
        screen.addstr(h - 1, 1, terminal_clip(footer, w - 2), c.A_DIM)
        screen.refresh()

    def activate(self, screen):
        if self.job and self.job.is_alive():
            return
        choice = self.selected

        # Custom dialog for country
        if choice == 3:
            c = self.curses
            h, w = screen.getmaxyx()
            prompt = "Двухбуквенный код страны (например DE, NL, US): "
            screen.addstr(h - 1, 1, " " * (w - 2))
            screen.addstr(h - 1, 1, terminal_clip(prompt, w - 10), c.A_BOLD)
            c.curs_set(1)
            c.echo()
            screen.timeout(-1)
            raw = screen.getstr(h - 1, len(prompt) + 1, 4).decode("utf-8", "replace").strip().upper()
            c.noecho()
            c.curs_set(0)
            screen.timeout(100)
            if not raw or raw not in REGIONS:
                self.message = f"Неизвестный код страны '{raw}'. Доступно: {', '.join(sorted(REGIONS)[:8])}..."
                return
            self.start_worker(choice, lambda: self.manager.apply(auto=False, country=raw, import_current=bool(not self.manager.state() and self.manager.legacy())))
            return

        # Direct launch
        if choice == 4:
            self.start_worker(choice, lambda: self.manager.launch_client("desktop"))
            return
        if choice == 5:
            self.start_worker(choice, lambda: self.manager.launch_client("cli"))
            return

        # Switch profile dialog
        if choice == 6:
            c = self.curses
            h, w = screen.getmaxyx()
            prompt = "Номер профиля для активации (1, 2...): "
            screen.addstr(h - 1, 1, " " * (w - 2))
            screen.addstr(h - 1, 1, terminal_clip(prompt, w - 10), c.A_BOLD)
            c.curs_set(1)
            c.echo()
            screen.timeout(-1)
            raw = screen.getstr(h - 1, len(prompt) + 1, 4).decode("utf-8", "replace").strip()
            c.noecho()
            c.curs_set(0)
            screen.timeout(100)
            if raw:
                self.start_worker(choice, lambda: self.manager.switch_profile(raw))
            return

        # Confirmation dialog for new profile or restore
        if choice in (7, 11):
            c = self.curses
            h, w = screen.getmaxyx()
            text = "Создать новый пустой профиль? [y/N]: " if choice == 7 else "Вернуть исходные команды? [y/N]: "
            screen.addstr(h - 1, 1, " " * (w - 2))
            screen.addstr(h - 1, 1, text, c.A_BOLD)
            c.echo()
            c.curs_set(1)
            screen.timeout(-1)
            ans = screen.getstr(h - 1, len(text) + 1, 2).decode("utf-8", "replace").strip().lower()
            c.noecho()
            c.curs_set(0)
            screen.timeout(100)
            if ans not in ("y", "yes", "д", "да"):
                self.message = "Отменено."
                return

        actions = {
            0: lambda: self.manager.show_status(),
            1: lambda: show_ip(self.manager.ip(), details=self.ip_details),
            2: lambda: self.manager.apply(auto=True, import_current=bool(not self.manager.state() and self.manager.legacy())),
            7: lambda: self.manager.apply(auto=self.manager.state()["auto_ip"] if self.manager.state() else True,
                                          country=self.manager.state()["region"]["country"] if self.manager.state() else None,
                                          rotate=True),
            8: lambda: self.manager.kill_hung_claude(),
            9: lambda: self.manager.create_manager_shortcut(),
            10: lambda: self.manager.apply(repair=True),
            11: lambda: self.manager.restore(),
        }
        if choice in actions:
            self.start_worker(choice, actions[choice])

    def start_worker(self, choice, fn):
        self.message = "Выполняю операцию…"
        def work():
            out = io.StringIO()
            failed = False
            try:
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    fn()
            except Error as e:
                failed = True
                out.write("Ошибка: " + clean(e) + "\n")
            except Exception as e:
                failed = True
                out.write("Непредвиденная ошибка: " + clean(e) + "\n")
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
                colours = (114, 217, 222, 117) if getattr(c, "COLORS", 0) >= 256 else (c.COLOR_GREEN, c.COLOR_RED, c.COLOR_YELLOW, c.COLOR_CYAN)
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
            elif key in (c.KEY_UP, ord("k")):
                self.selected = (self.selected - 1) % len(self.ACTIONS)
                self.scroll = 0
                self.details = self.ip_details = False
            elif key in (c.KEY_DOWN, ord("j"), 9):
                self.selected = (self.selected + 1) % len(self.ACTIONS)
                self.scroll = 0
                self.details = self.ip_details = False
            elif ord("1") <= key <= ord("9"):
                target = key - ord("1")
                if target < len(self.ACTIONS):
                    self.selected = target
                    self.scroll = 0
                    self.details = self.ip_details = False
            elif key == ord("0"):
                self.selected = len(self.ACTIONS) - 1
                self.scroll = 0
                self.details = self.ip_details = False
            elif key in (10, 13, getattr(c, "KEY_ENTER", 10)):
                if screen.getmaxyx()[0] >= 18 and screen.getmaxyx()[1] >= 52:
                    self.activate(screen)
            elif key == getattr(c, "KEY_NPAGE", -1):
                self.scroll += 5
            elif key == getattr(c, "KEY_PPAGE", -1):
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
    setup_windows_console()
    elevate_privileges()
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
    elif args.action == "ping":
        print("Проверяю доступность серверов Claude…")
        for probe in check_claude_connectivity():
            tag = "[OK]" if probe["ok"] else "[!!]"
            latency = f"({probe['ms']} ms)" if probe.get("ms") is not None else ""
            print(f"{tag} {probe['name']}: {probe['note']} {latency}")
    elif args.action == "profiles":
        profs = manager.list_profiles()
        if not profs:
            print("Профили ещё не созданы.")
        else:
            print("Список профилей:")
            for idx, p in enumerate(profs, 1):
                act = " [АКТИВЕН]" if p["active"] else ""
                auth = " [Есть вход]" if p["has_auth"] else " [Чистый]"
                print(f"  {idx}. {p['name']} ({p['date']}){auth}{act}")
    elif args.action == "switch":
        manager.switch_profile(args.target)
    elif args.action == "launch":
        manager.launch_client(args.kind)
    elif args.action == "kill":
        manager.kill_hung_claude()
    elif args.action == "shortcut":
        manager.create_manager_shortcut()
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
