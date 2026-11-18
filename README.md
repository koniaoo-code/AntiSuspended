СПАСИБО НАРЕЗАННОМУ # AntiSuspended for Windows (Native Edition)

Полноценная расширенная версия и автономный **.exe** для Windows: отдельные изолированные профили Claude Desktop и Claude Code CLI, региональные настройки по выходному IP, встроенная проверка сети и рисков, переключение между аккаунтами и запуск в 1 клик.

> **Готовый EXE**: `dist\AntiSuspended.exe` — работает автономно, не требует установки Python.  
> **Иконка**: Встроенный официальный логотип-щит в терракотово-коралловой стилистике Claude с поддержкой разрешений 16x16–256x256.  
> **UAC / Права администратора**: Автоматический запрос прав администратора (UAC Elevation) через манифест приложения.

---

## Что адаптировано идеально под Windows

1. **Запрос прав администратора (UAC)**:
   - В исполняемый файл вшит манифест `requireAdministrator`. В Проводнике Windows файл отмечен щитом UAC, а при запуске запрашивает права администратора для корректной работы с реестром, сетевыми сокетами и процессами.
2. **Фирменная иконка и логотип**:
   - В `.exe` вшита качественная многослойная иконка `app_icon.ico` (256x256, 128x128, 64x64, 48x48, 32x32, 24x24, 16x16) со стилизованным щитом защиты и ядром Claude.
   - Возможность создать красивый ярлык `AntiSuspended.lnk` на Рабочем столе в 1 клик.
3. **Поддержка Windows 11 MSIX Store Claude Desktop**:
   - Автоматически находит как стандартный Anthropic инсталлятор (`%LOCALAPPDATA%\AnthropicClaude`), так и современную версию из Microsoft Store / WindowsApps (`claude-desktop.exe`, `Claude_pzs8sxrjxfjjc`).
   - Исключена путаница между CLI-утилитой `claude.exe` (Claude Code) и графическим Claude Desktop.
4. **Снятие зависших процессов (Process Singleton Fix)**:
   - При сбоях или аварийном закрытии Electron оставляет фоновые процессы, блокирующие запуск (`Lock file can not be created`). Встроенная функция `kill` моментально очищает зависшие копии перед запуском.
5. **Адаптация консоли Windows**:
   - Автоматическая установка заголовка окна консоли: `AntiSuspended - Claude Profile Manager (Windows)`.
   - Включение Virtual Terminal Processing (ANSI escape-последовательности и 24-битный цвет в `cmd.exe` и PowerShell).
   - Кодировка UTF-8 (`chcp 65001`) для идеального отображения кириллицы и рамок.
6. **Интеграция с Windows Registry и PATH**:
   - Автоматическое добавление каталога обёрток в пользовательский `PATH` (`HKCU\Environment\Path`) с отправкой сообщения `WM_SETTINGCHANGE` (работает сразу во всех новых окнах без перезагрузки системы).

---

## Меню управления

- `1` — **Обзор и статус**: проверка 10 пунктов локальной изоляции (оценка 10/10).
- `2` — **Проверить сеть и Claude**: выходной IP, геолокация, провайдер, VPN/хостинг, риск-скор и проверка доступности `claude.ai` и API.
- `3` — **Авто-настройка по IP**: настройка всего в 1 клик (часовой пояс и язык выставятся по текущему IP).
- `4` — **Задать страну вручную**: выбор конкретной страны (например, `NL`, `DE`, `US`).
- `5` — **Запустить Claude Desktop**: запуск изолированного десктоп-клиента с текущим профилем.
- `6` — **Запустить Claude Code**: запуск CLI в новом окне терминала.
- `7` — **Сменить профиль**: выбор и активация любого существующего профиля (мультиаккаунт).
- `8` — **Новый пустой профиль**: ротация профиля для входа в новый аккаунт.
- `9` — **Снять зависшие процессы Claude**: принудительное завершение фоновых копий при блокировке.
- `10` — **Ярлык на Рабочем столе**: создание ярлыка `AntiSuspended` с фирменной иконкой.
- `11` — **Починить ярлыки**: восстановление команд, ярлыка Claude Desktop и PATH.
- `12` — **Откатить установку**: возврат к стандартным настройкам без удаления данных профилей.
- `0` — **Выход**.

---

## Команды CLI для скриптов и автоматизации

```cmd
AntiSuspended.exe status          # Проверка настроек и оценка изоляции
AntiSuspended.exe ping            # Проверка доступности серверов Claude и Cloudflare
AntiSuspended.exe ip              # Проверка IP, сети и Cloudflare
AntiSuspended.exe ip --details    # Расширенный технический отчёт о сети
AntiSuspended.exe apply           # Применить изоляцию с регионом по IP
AntiSuspended.exe apply --country NL # Применить с регионом Нидерландов
AntiSuspended.exe launch desktop  # Запустить Claude Desktop с изолированным профилем
AntiSuspended.exe launch cli      # Запустить Claude Code CLI
AntiSuspended.exe kill            # Завершить зависшие фоновые процессы Claude
AntiSuspended.exe shortcut        # Создать ярлык AntiSuspended на Рабочем столе
AntiSuspended.exe profiles        # Показать список всех профилей
AntiSuspended.exe switch 1        # Переключиться на профиль №1
AntiSuspended.exe rotate          # Создать новый пустой профиль
AntiSuspended.exe repair          # Восстановить обёртки и ярлыки
AntiSuspended.exe restore         # Откатить команды
```

---

## Сборка из исходного кода

```cmd
pip install -r requirements.txt
python build_exe.py
```

Скрипт сборщика `build_exe.py` автоматически внедряет манифест прав администратора (`--uac-admin`), встроенную иконку (`--icon app_icon.ico`) и базу данных таймзон (`tzdata`).

---

## Расположение данных в Windows

- **Настройки и резервные копии**:  
  `%APPDATA%\claude-profile-manager\` (`C:\Users\<Имя>\AppData\Roaming\claude-profile-manager\`)
- **Каталоги профилей (сессии, куки, локальные ID)**:  
  `%LOCALAPPDATA%\claude-profile-manager\profiles\`
- **Команды-обёртки**:  
  `%LOCALAPPDATA%\claude-profile-manager\bin\` (`claude.cmd`, `claude-desktop.cmd`, `claude-profile-manager.cmd`)
- **Ярлыки на Рабочем столе**:  
  `%USERPROFILE%\Desktop\AntiSuspended.lnk`  
  `%USERPROFILE%\Desktop\Claude (Isolated).lnk`
