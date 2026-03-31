import json
import sqlite3
import sys
import os
import subprocess
from collections import defaultdict
import telebot
import time
import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import argparse
import requests

MSK_TZ = datetime.timezone(datetime.timedelta(hours=3))

from geoip import init_geo_db, get_ips_geo_info

def load_config(path: str) -> dict:
    """
    Чтение JSON файла конфигурации и валидация обязательных полей.
    """
    if not os.path.exists(path):
        print(f"Ошибка: Файл конфигурации '{path}' не найден.", file=sys.stderr)
        sys.exit(1)
        
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Ошибка: Невалидный JSON формат в файле '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при чтении файла конфигурации '{path}': {e}", file=sys.stderr)
        sys.exit(1)
        
    # Валидация обязательных полей
    telegramConfig = config.get("telegram")
    if not isinstance(telegramConfig, dict):
        print("Ошибка: В конфигурации отсутствует секция 'telegram' или она имеет неверный формат.", file=sys.stderr)
        sys.exit(1)
        
    bot_token = telegramConfig.get("bot_token")
    chat_id = telegramConfig.get("chat_id")
    
    if not bot_token or not chat_id:
        print("Ошибка: В конфигурации отсутствуют обязательные поля telegram.bot_token или telegram.chat_id.", file=sys.stderr)
        sys.exit(1)
        
    return config

def init_db(db_path: str) -> sqlite3.Connection:
    """
    Инициализация базы данных SQLite и создание необходимых таблиц.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            total_connections INTEGER NOT NULL,
            unique_ips INTEGER NOT NULL,
            bytes_in INTEGER NOT NULL DEFAULT 0,
            bytes_out INTEGER NOT NULL DEFAULT 0,
            top_ips_json TEXT
        );
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            alert_type TEXT NOT NULL,       -- 'warning_ip', 'critical_leak', 'down'
            alert_key TEXT NOT NULL,        -- IP или 'global'
            message TEXT
        );
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_state (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(timestamp);')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);')
        
        conn.commit()
        
        init_geo_db(conn)
        
        return conn
    except sqlite3.Error as e:
        print(f"Ошибка SQLite при инициализации базы данных '{db_path}': {e}", file=sys.stderr)
        sys.exit(1)

def collect_connections(port: int) -> dict:
    """Сбор активных подключений через команду ss."""
    per_ip = defaultdict(int)
    total = 0
    
    try:
        result = subprocess.run(
            ["ss", "-tn", "sport", "=", f":{port}"],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        
        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 5:
                # Обычно 5-ая колонка - Peer Address:Port
                peer_address_port = parts[4]
                if peer_address_port.startswith('['):
                    # IPv6
                    ip_part = peer_address_port[1:peer_address_port.rfind(']')]
                else:
                    # IPv4
                    ip_part = peer_address_port.rsplit(':', 1)[0]
                per_ip[ip_part] += 1
                total += 1
    except Exception:
        pass
        
    return {
        "total": total,
        "unique_ips": len(per_ip),
        "per_ip": dict(per_ip)
    }

def collect_traffic(db_conn: sqlite3.Connection = None, port: int = 8443) -> dict:
    """Сбор метрик трафика через iptables. Дельта вычисляется на основе 'prev_bytes_in/out'."""
    current_in = 0
    current_out = 0
    
    try:
        result = subprocess.run(
            ["iptables", "-L", "MTPROXY_MONITOR", "-n", "-v", "-x"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[2:]:  # skip headers
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        bytes_count = int(parts[1])
                        if f"dpt:{port}" in line:
                            current_in += bytes_count
                        elif f"spt:{port}" in line:
                            current_out += bytes_count
                    except ValueError:
                        pass
    except Exception:
        pass
        
    delta_in = 0
    delta_out = 0
    
    if db_conn:
        try:
            cursor = db_conn.cursor()
            
            cursor.execute("SELECT value FROM bot_state WHERE key = 'prev_bytes_in'")
            row_in = cursor.fetchone()
            prev_in = int(row_in[0]) if row_in else 0
            
            cursor.execute("SELECT value FROM bot_state WHERE key = 'prev_bytes_out'")
            row_out = cursor.fetchone()
            prev_out = int(row_out[0]) if row_out else 0
            
            delta_in = current_in - prev_in if current_in >= prev_in else current_in
            delta_out = current_out - prev_out if current_out >= prev_out else current_out
            
            cursor.execute("INSERT OR REPLACE INTO bot_state (key, value) VALUES ('prev_bytes_in', ?)", (str(current_in),))
            cursor.execute("INSERT OR REPLACE INTO bot_state (key, value) VALUES ('prev_bytes_out', ?)", (str(current_out),))
            db_conn.commit()
        except Exception as e:
            # Игнорируем ошибки БД при обновлении стейта, чтобы скрипт продолжал работать
            pass
            
    return {
        "bytes_in": delta_in,
        "bytes_out": delta_out
    }

def check_mtproxy_alive() -> bool:
    """Проверка доступности процесса mtproto-proxy."""
    try:
        # returns 0 if found
        result = subprocess.run(["pgrep", "mtproto-proxy"], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False

def send_message(bot_token: str, chat_id: str, text: str, parse_mode: str = "HTML") -> bool:
    """
    Отправка сообщения в Telegram с ретраями.
    """
    for _ in range(3):
        try:
            bot = telebot.TeleBot(bot_token)
            bot.send_message(chat_id, text, parse_mode=parse_mode)
            return True
        except Exception:
            time.sleep(2)
    return False

def send_photo(bot_token: str, chat_id: str, photo_path: str, caption: str = "") -> bool:
    """
    Отправка фото в Telegram с ретраями.
    """
    for _ in range(3):
        try:
            bot = telebot.TeleBot(bot_token)
            with open(photo_path, 'rb') as photo:
                bot.send_photo(chat_id, photo, caption=caption)
            return True
        except Exception:
            time.sleep(2)
    return False

def format_bytes(n: int) -> str:
    """Форматирование байтов в человекочитаемый вид."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            if unit == 'B':
                return f"{n} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"

def check_and_alert(conns: dict, traffic: dict, config: dict, db: sqlite3.Connection):
    """
    Проверка порогов, анти-флуд, формирование сообщений алертов.
    """
    cursor = db.cursor()
    telegram_config = config.get("telegram", {})
    bot_token = telegram_config.get("bot_token")
    chat_id = telegram_config.get("chat_id")
    if not bot_token or not chat_id:
        return

    thresholds = config.get("thresholds", {})
    max_conn_per_ip = thresholds.get("max_connections_per_ip", 20)
    max_unique_ips = thresholds.get("max_unique_ips", 50)
    cooldown_min = config.get("alert_cooldown_minutes", 30)

    now = int(time.time())
    cooldown_sec = cooldown_min * 60

    def can_send_alert(alert_type: str, alert_key: str) -> bool:
        cursor.execute(
            "SELECT timestamp FROM alerts WHERE alert_type = ? AND alert_key = ? ORDER BY timestamp DESC LIMIT 1",
            (alert_type, alert_key)
        )
        row = cursor.fetchone()
        if row:
            last_ts = row[0]
            if now - last_ts < cooldown_sec:
                return False
        return True

    def record_alert(alert_type: str, alert_key: str, message: str):
        cursor.execute(
            "INSERT INTO alerts (timestamp, alert_type, alert_key, message) VALUES (?, ?, ?, ?)",
            (now, alert_type, alert_key, message)
        )
        db.commit()

    # 1. Проверяем check_mtproxy_alive()
    if not check_mtproxy_alive():
        alert_type = "down"
        alert_key = "global"
        if can_send_alert(alert_type, alert_key):
            msg = (
                "🔴 MTProxy DOWN\n\n"
                "Процесс mtproto-proxy не обнаружен.\n"
                "systemctl status: inactive (dead)"
            )
            if send_message(bot_token, chat_id, msg):
                record_alert(alert_type, alert_key, msg)
        return

    # 2. WARNING
    per_ip = conns.get("per_ip", {})
    total = conns.get("total", 0)
    unique_ips = conns.get("unique_ips", 0)
    bytes_in = traffic.get("bytes_in", 0)
    bytes_out = traffic.get("bytes_out", 0)

    for ip, count in per_ip.items():
        if count > max_conn_per_ip:
            alert_type = "warning_ip"
            alert_key = ip
            if can_send_alert(alert_type, alert_key):
                geo_info = get_ips_geo_info([ip], db).get(ip, "")
                msg = (
                    f"⚠️ MTProxy WARNING\n\n"
                    f"IP {ip}{geo_info} — {count} подключений (порог: {max_conn_per_ip})\n\n"
                    f"Всего: {total} conn | {unique_ips} unique IPs\n"
                    f"Трафик за 5 мин: ↓{format_bytes(bytes_out)} ↑{format_bytes(bytes_in)}"
                )
                if send_message(bot_token, chat_id, msg):
                    record_alert(alert_type, alert_key, msg)

    # 3. CRITICAL
    if unique_ips > max_unique_ips:
        alert_type = "critical_leak"
        alert_key = "global"
        if can_send_alert(alert_type, alert_key):
            sorted_ips = sorted(per_ip.items(), key=lambda x: x[1], reverse=True)[:10]
            top_ips_list = [ip for ip, count in sorted_ips]
            geo_map = get_ips_geo_info(top_ips_list, db)
            
            top_ips_str = "\n".join([f"  {ip}{geo_map.get(ip, '')} — {count} conn" for ip, count in sorted_ips])
            
            msg = (
                f"🚨 MTProxy LEAK ALERT\n\n"
                f"Обнаружено {unique_ips} уникальных IP (порог: {max_unique_ips})\n\n"
                f"Top 10:\n{top_ips_str}\n\n"
                f"Трафик за 5 мин: ↓{format_bytes(bytes_out)} ↑{format_bytes(bytes_in)}"
            )
            if send_message(bot_token, chat_id, msg):
                record_alert(alert_type, alert_key, msg)

def generate_daily_chart(db: sqlite3.Connection, output_path: str, start_ts: int = None) -> str:
    """Генерация графика."""
    cursor = db.cursor()
    now = int(time.time())
    if start_ts is None:
        start_ts = now - 86400
    
    cursor.execute("""
        SELECT timestamp, total_connections, unique_ips, bytes_in, bytes_out 
        FROM metrics 
        WHERE timestamp > ? 
        ORDER BY timestamp
    """, (start_ts,))
    
    rows = cursor.fetchall()
    
    timestamps = [datetime.datetime.fromtimestamp(row[0], tz=MSK_TZ) for row in rows]
    conns = [row[1] for row in rows]
    ips = [row[2] for row in rows]
    b_in = [row[3] / (1024*1024) for row in rows] # in MB
    b_out = [row[4] / (1024*1024) for row in rows] # in MB

    plt.style.use('dark_background')
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
    
    # Верхний график
    color_conn = '#00e5ff'
    ax1.plot(timestamps, conns, color=color_conn, label='Connections')
    ax1.set_ylabel('Connections', color=color_conn)
    ax1.tick_params(axis='y', labelcolor=color_conn)
    
    ax1_ips = ax1.twinx()
    color_ips = '#ff00ff'
    ax1_ips.plot(timestamps, ips, color=color_ips, label='Unique IPs', linestyle='dashed')
    ax1_ips.set_ylabel('Unique IPs', color=color_ips)
    ax1_ips.tick_params(axis='y', labelcolor=color_ips)
    
    lines_1, labels_1 = ax1.get_legend_handles_labels()
    lines_2, labels_2 = ax1_ips.get_legend_handles_labels()
    ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper left')
    
    ax1.set_title(f"MTProxy Load - {datetime.datetime.now(MSK_TZ).strftime('%d.%m.%Y')}")
    ax1.grid(True, alpha=0.3)

    # Нижний график (трафик)
    width = 0.003 # ширина
    if not timestamps:
        timestamps = [datetime.datetime.now(MSK_TZ)]
        b_in = [0]
        b_out = [0]
        
    ax2.bar(timestamps, b_out, width=width, label='Down (MB)', color='#00ff00', alpha=0.7)
    ax2.bar(timestamps, b_in, width=width, bottom=b_out, label='Up (MB)', color='#ffaa00', alpha=0.7)
    
    ax2.set_ylabel('Traffic (MB / 5 min)')
    ax2.legend(loc='upper left')
    ax2.grid(True, alpha=0.3)

    ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.xticks(rotation=45)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight')
    plt.close(fig)
    
    return output_path

def send_daily_report(config: dict, db: sqlite3.Connection, start_ts: int = None):
    """
    Формирование и отправка суточного отчета.
    """
    cursor = db.cursor()
    telegram_config = config.get("telegram", {})
    bot_token = telegram_config.get("bot_token")
    chat_id = telegram_config.get("chat_id")
    if not bot_token or not chat_id:
        return

    now = int(time.time())
    if start_ts is None:
        start_ts = now - 86400
    
    # 1. Агрегаты
    cursor.execute("""
        SELECT MAX(total_connections), AVG(total_connections),
               MAX(unique_ips), AVG(unique_ips),
               SUM(bytes_in), SUM(bytes_out)
        FROM metrics
        WHERE timestamp > ?
    """, (start_ts,))
    row = cursor.fetchone()
    if not row or row[0] is None:
        max_conn, avg_conn, max_ips, avg_ips, sum_in, sum_out = 0, 0, 0, 0, 0, 0
    else:
        max_conn, avg_conn, max_ips, avg_ips, sum_in, sum_out = row
        avg_conn = int(avg_conn) if avg_conn else 0
        avg_ips = int(avg_ips) if avg_ips else 0

    # 2. Top-IPs
    cursor.execute("SELECT top_ips_json FROM metrics WHERE timestamp > ?", (start_ts,))
    rows = cursor.fetchall()
    
    ip_totals = defaultdict(int)
    for r in rows:
        if r[0]:
            try:
                top_data = json.loads(r[0])
                for ip, count in top_data.items():
                    ip_totals[ip] += count
            except Exception:
                pass
                
    top_n = config.get("daily_report_top_n", 10)
    sorted_ips = sorted(ip_totals.items(), key=lambda x: x[1], reverse=True)[:top_n]
    
    top_ips_list = [ip for ip, count in sorted_ips]
    geo_map = get_ips_geo_info(top_ips_list, db)
    
    top_ips_str = ""
    for i, (ip, count) in enumerate(sorted_ips):
        suffix = " (суммарно)" if i == 0 else ""
        geo_info = geo_map.get(ip, "")
        top_ips_str += f"  {ip}{geo_info} — {count} conn{suffix}\n"
        
    if not top_ips_str:
        top_ips_str = "  Нет данных\n"
        
    # 3. Алерты
    cursor.execute("""
        SELECT alert_type, COUNT(*) 
        FROM alerts 
        WHERE timestamp > ? 
        GROUP BY alert_type
    """, (start_ts,))
    
    alerts_counts = {}
    for r in cursor.fetchall():
        alerts_counts[r[0]] = r[1]
        
    warn_count = alerts_counts.get("warning_ip", 0)
    crit_count = alerts_counts.get("critical_leak", 0)

    # 4. Текст отчета
    date_str = datetime.datetime.now(MSK_TZ).strftime("%d.%m.%Y")
    
    text = (
        f"📊 MTProxy — Отчёт за {date_str}\n\n"
        f"Подключений (пик / среднее): {max_conn} / {avg_conn}\n"
        f"Уникальных IP (всего / пик / среднее): {len(ip_totals)} / {max_ips} / {avg_ips}\n"
        f"Трафик: ↓{format_bytes(sum_out or 0)} ↑{format_bytes(sum_in or 0)}\n\n"
        f"Top {top_n} IP за сутки:\n{top_ips_str}\n"
        f"Алертов за сутки: {warn_count} WARNING, {crit_count} CRITICAL"
    )
    
    # 5. График
    output_path = "/tmp/mtproxy_daily.png"
    generate_daily_chart(db, output_path, start_ts)
    
    # 6. Отправка
    send_photo(bot_token, chat_id, output_path, caption=text)

def process_bot_commands(bot_token: str, chat_id: str, db: sqlite3.Connection, config: dict, recent_conns: dict = None, recent_traffic: dict = None):
    """
    Обработка входящих команд Telegram.
    """
    bot = telebot.TeleBot(bot_token)
    cursor = db.cursor()
    
    # Читаем offset из bot_state
    cursor.execute("SELECT value FROM bot_state WHERE key = 'telegram_offset'")
    row = cursor.fetchone()
    offset = int(row[0]) if row is not None else None

    # Запрашиваем updates
    try:
        updates = bot.get_updates(offset=offset, timeout=1)
    except Exception:
        return

    if not updates:
        return

    for update in updates:
        offset = update.update_id + 1
        
        # Проверяем, что есть сообщение и текст
        if not update.message or not update.message.text:
            continue
            
        # Защита: команды принимаются только от владельца, указанного в конфигурации
        if str(update.message.chat.id) != str(chat_id):
            continue
            
        text = update.message.text.strip()
        
        if text == "/status" or text.startswith("/status@"):
            if recent_conns and recent_traffic:
                connections = recent_conns
                traffic = recent_traffic
            else:
                port = config.get("mtproxy_port", 8443)
                connections = collect_connections(port)
                traffic = collect_traffic(db, port)
            
            alive = check_mtproxy_alive()
            
            per_ip = connections.get("per_ip", {})
            sorted_ips = sorted(per_ip.items(), key=lambda x: x[1], reverse=True)[:10]
            
            top_ips_list = [ip for ip, count in sorted_ips]
            geo_map = get_ips_geo_info(top_ips_list, db)
            
            top_ips_str = "\n".join([f"  <code>{ip}</code>{geo_map.get(ip, '')} — {count}" for ip, count in sorted_ips])
            
            status_text = f"<b>MTProxy Status:</b> {'✅ Alive' if alive else '❌ Down'}\n\n"
            status_text += f"<b>Connections:</b> {connections['total']}\n"
            status_text += f"<b>Unique IPs:</b> {connections['unique_ips']}\n\n"
            
            if top_ips_str:
                status_text += f"<b>Top 10 IPs:</b>\n{top_ips_str}\n\n"
            
            status_text += f"<b>Traffic (delta):</b>\n"
            status_text += f"↓ Down: {format_bytes(traffic['bytes_out'])}\n"
            status_text += f"↑ Up: {format_bytes(traffic['bytes_in'])}"
            
            status_text += f"\n\n<i>(замер: {datetime.datetime.now(MSK_TZ).strftime('%H:%M:%S')})</i>"
            
            send_message(bot_token, chat_id, status_text)
            
        elif text == "/today" or text.startswith("/today@"):
            today_start = int(datetime.datetime.now(MSK_TZ).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
            send_daily_report(config, db, start_ts=today_start)
            
        elif text.startswith("/threshold"):
            parts = text.split()
            if len(parts) == 3:
                param = parts[1]
                value = parts[2]
                try:
                    value = int(value)
                    
                    if "thresholds" not in config:
                        config["thresholds"] = {}
                        
                    if param in ["warning", "max_connections_per_ip"]:
                        config["thresholds"]["max_connections_per_ip"] = value
                        success_msg = f"✅ Threshold 'max_connections_per_ip' updated to {value}."
                    elif param in ["critical", "max_unique_ips"]:
                        config["thresholds"]["max_unique_ips"] = value
                        success_msg = f"✅ Threshold 'max_unique_ips' updated to {value}."
                    else:
                        success_msg = "❌ Unknown parameter. Use 'warning' or 'critical'."
                    
                    if "✅" in success_msg:
                        # Обновляем config.json (ожидаем, что он в текущей папке скрипта)
                        import json
                        config_path = "config.json"
                        # Попытка проверить, существует ли переданный путь из sys.argv
                        import sys
                        if len(sys.argv) > 1 and sys.argv[1].endswith(".json"):
                            config_path = sys.argv[1]
                            
                        with open(config_path, "w", encoding="utf-8") as f:
                            json.dump(config, f, indent=4, ensure_ascii=False)
                            
                    send_message(bot_token, chat_id, success_msg)
                except ValueError:
                    send_message(bot_token, chat_id, "❌ Invalid value. Must be integer.")
            else:
                send_message(bot_token, chat_id, "Usage: /threshold &lt;warning|critical&gt; &lt;value&gt;")
                
        elif text == "/help" or text.startswith("/help@"):
            help_text = (
                "<b>Доступные команды:</b>\n"
                "/status - Текущий статус прокси\n"
                "/today - Отчет за день\n"
                "/threshold &lt;param&gt; &lt;value&gt; - Изменить лимиты (warning/critical)\n"
                "/help - Справка"
            )
            send_message(bot_token, chat_id, help_text)

    # Сохраняем новый offset
    cursor.execute("INSERT OR REPLACE INTO bot_state (key, value) VALUES ('telegram_offset', ?)", (str(offset),))
    db.commit()

def main():
    parser = argparse.ArgumentParser(description="MTProxy Monitor")
    parser.add_argument("--collect", action="store_true", help="Сбор метрик + алерты + обработка команд бота")
    parser.add_argument("--daily-report", action="store_true", help="Суточный отчёт с графиком")
    parser.add_argument("--config", type=str, default="./config.json", help="Путь к config.json (default: ./config.json)")
    parser.add_argument("--db", type=str, default="./data/metrics.db", help="Путь к БД (default: ./data/metrics.db)")
    
    args = parser.parse_args()
    
    if not (args.collect or args.daily_report):
        parser.print_help()
        sys.exit(1)
        
    config = load_config(args.config)
    
    # Ensure db directory exists if it's not current dir or absolute
    db_dir = os.path.dirname(args.db)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except Exception as e:
            print(f"Ошибка при создании директории БД: {e}", file=sys.stderr)
            sys.exit(1)
            
    db = init_db(args.db)
    
    try:
        if args.collect:
            port = config.get("mtproxy_port", 8443)
            conns = collect_connections(port)
            traffic = collect_traffic(db, port)
            
            # Record into SQLite
            now = int(time.time())
            total = conns.get("total", 0)
            unique = conns.get("unique_ips", 0)
            
            # Optional: do not store full IP list directly in per_ip if it's too large, 
            # but task implies top_ips_json could just be all IPs or part of it. We'll store conns.get("per_ip", {})
            top_ips = json.dumps(conns.get("per_ip", {}))
            
            b_in = traffic.get("bytes_in", 0)
            b_out = traffic.get("bytes_out", 0)
            
            cursor = db.cursor()
            cursor.execute('''
                INSERT INTO metrics (timestamp, total_connections, unique_ips, bytes_in, bytes_out, top_ips_json)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (now, total, unique, b_in, b_out, top_ips))
            db.commit()
            
            check_and_alert(conns, traffic, config, db)
            
            telegram_config = config.get("telegram", {})
            bot_token = telegram_config.get("bot_token")
            chat_id = telegram_config.get("chat_id")
            if bot_token and chat_id:
                process_bot_commands(bot_token, chat_id, db, config, recent_conns=conns, recent_traffic=traffic)
                
        if args.daily_report:
            send_daily_report(config, db)
    finally:
        db.close()

if __name__ == "__main__":
    main()
