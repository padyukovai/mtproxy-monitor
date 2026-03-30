# MTProxy Monitor

Лёгкая система мониторинга для [MTProto Proxy](https://github.com/TelegramMessenger/MTProxy), работающая на слабых VPS.

## Что это делает

- **Каждые 5 минут**: собирает число TCP-подключений, уникальных IP, трафик через iptables → сохраняет в SQLite
- **Алерты в Telegram**:
  - ⚠️ WARNING — подозрительный IP (>20 подключений с одного адреса)
  - 🚨 CRITICAL — возможная утечка адреса (>50 уникальных IP)
  - 🔴 DOWN — MTProxy не отвечает
- **Ежедневно в 00:05**: отчёт за сутки + PNG-график нагрузки
- **Команды бота** (ответ в течение 5 мин): `/status`, `/today`, `/threshold`, `/help`

## Требования

- Ubuntu 22.04 / 24.04
- Python 3.10+
- MTProxy на порту 8443
- Telegram-бот (инструкция ниже)

## Установка

### 1. Создайте Telegram-бота

1. Откройте Telegram и найдите [@BotFather](https://t.me/BotFather)
2. Отправьте `/newbot`, следуйте инструкциям
3. Получите **токен** вида `123456789:AAF...` — сохраните его

### 2. Узнайте chat_id

1. Отправьте любое сообщение вашему новому боту
2. Перейдите в браузере по ссылке:
   ```
   https://api.telegram.org/bot<ВАШ_ТОКЕН>/getUpdates
   ```
3. Найдите в JSON поле `"id"` внутри `"chat"` — это ваш `chat_id`

### 3. Скопируйте файлы на сервер

```bash
# Находясь в папке репозитория на вашем ПК:
scp -r . root@<IP_СЕРВЕРА>:/tmp/mtproxy-monitor
```

### 4. Запустите установку

```bash
ssh root@<IP_СЕРВЕРА>
cd /tmp/mtproxy-monitor
chmod +x install.sh
./install.sh
```

Скрипт автоматически:
- Установит зависимости (pyTelegramBotAPI, matplotlib)
- Создаст `/opt/mtproxy-monitor/` с данными
- Настроит iptables-счётчики трафика
- Установит и запустит systemd-таймеры

> **Примечание:** После установки системный таймер сразу начнёт работу и в первые минуты будет генерировать ошибки в логах, так как токен бота ещё не настроен. Это нормально; после заполнения конфига ошибки исчезнут.

### 5. Заполните конфиг

```bash
nano /opt/mtproxy-monitor/config.json
```

```json
{
    "telegram": {
        "bot_token": "123456789:AAF...",
        "chat_id": "123456789"
    },
    "thresholds": {
        "max_connections_per_ip": 20,
        "max_unique_ips": 50
    },
    "mtproxy_port": 8443,
    "alert_cooldown_minutes": 30,
    "daily_report_top_n": 10
}
```

## Проверка работы

```bash
# Статус таймеров
systemctl status mtproxy-monitor.timer
systemctl status mtproxy-monitor-daily.timer

# Запустить сбор вручную (не ждать 5 мин)
systemctl start mtproxy-monitor.service

# Логи последнего запуска
journalctl -u mtproxy-monitor.service -n 50

# Запустить суточный отчёт вручную
systemctl start mtproxy-monitor-daily.service
```

## Структура файлов

```
/opt/mtproxy-monitor/
├── monitor.py          # Основной скрипт
├── config.json         # Конфигурация
└── data/
    └── metrics.db      # SQLite-база с историей

/etc/systemd/system/
├── mtproxy-monitor.service        # oneshot: сбор + алерты
├── mtproxy-monitor.timer          # каждые 5 мин
├── mtproxy-monitor-daily.service  # oneshot: суточный отчёт
└── mtproxy-monitor-daily.timer    # ежедневно в 00:05
```

## Команды бота

| Команда | Описание |
|---|---|
| `/status` | Текущий снапшот (подключения, IP, трафик) |
| `/today` | Промежуточная статистика за сегодня |
| `/threshold warning 30` | Изменить порог на лету (или `max_connections_per_ip`) |
| `/threshold critical 100` | Изменить порог утечки (или `max_unique_ips`) |
| `/help` | Список команд |

> **Важно**: бот не работает в режиме long-polling. Команды обрабатываются при каждом запуске таймера (каждые 5 минут). Максимальная задержка ответа — 5 минут.

## Потребление ресурсов

- RAM в штатном режиме: ~15–20 MB
- RAM в пике (генерация графика): ~25–30 MB
- Диск: ~30 MB (зависимости) + данные SQLite (~1–5 MB/мес)
