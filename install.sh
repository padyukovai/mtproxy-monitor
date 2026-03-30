#!/bin/bash
set -e

echo "=== Установка MTProxy Monitor ==="

# Проверка root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Запускайте скрипт от root (sudo ./install.sh)" >&2
    exit 1
fi

# 1. Зависимости
echo "[1/5] Установка зависимостей..."
apt-get update -qq
apt-get install -y python3-pip python3-matplotlib
pip3 install pyTelegramBotAPI --break-system-packages

# 2. Директории
echo "[2/5] Создание директорий..."
mkdir -p /opt/mtproxy-monitor/data

# 3. Файлы
echo "[3/5] Копирование файлов..."
cp monitor.py /opt/mtproxy-monitor/
if [ ! -f /opt/mtproxy-monitor/config.json ]; then
    cp config.example.json /opt/mtproxy-monitor/config.json
    echo "⚠️  Заполните /opt/mtproxy-monitor/config.json (bot_token, chat_id)"
else
    echo "   config.json уже существует, пропускаем."
fi

# 4. iptables
echo "[4/5] Настройка iptables..."
if ! iptables -L MTPROXY_MONITOR -n >/dev/null 2>&1; then
    iptables -N MTPROXY_MONITOR
    iptables -A MTPROXY_MONITOR -p tcp --dport 8443 -j RETURN
    iptables -A MTPROXY_MONITOR -p tcp --sport 8443 -j RETURN
    iptables -I INPUT 1 -j MTPROXY_MONITOR
    iptables -I OUTPUT 1 -j MTPROXY_MONITOR
    echo "   iptables chain MTPROXY_MONITOR создана."
    # Сохранить правила, чтобы пережили ребут
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'active'; then
        echo "   UFW активен. Добавляем правила в /etc/ufw/before.rules"
        if ! grep -q "MTPROXY_MONITOR" /etc/ufw/before.rules; then
            sed -i '/^\*filter/a :MTPROXY_MONITOR - [0:0]\n-A MTPROXY_MONITOR -p tcp --dport 8443 -j RETURN\n-A MTPROXY_MONITOR -p tcp --sport 8443 -j RETURN\n-I INPUT 1 -j MTPROXY_MONITOR\n-I OUTPUT 1 -j MTPROXY_MONITOR' /etc/ufw/before.rules
            ufw reload >/dev/null
        fi
    else
        echo "   UFW не используется. Устанавливаем iptables-persistent..."
        apt-get install -y iptables-persistent
        netfilter-persistent save
    fi
else
    echo "   iptables chain MTPROXY_MONITOR уже существует, пропускаем."
fi

# 5. Systemd
echo "[5/5] Установка systemd-юнитов..."
cp systemd/*.service systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mtproxy-monitor.timer
systemctl enable --now mtproxy-monitor-daily.timer

echo ""
echo "=== Установка завершена ==="
echo ""
echo "Следующий шаг: заполните конфиг, если ещё не сделали:"
echo "  nano /opt/mtproxy-monitor/config.json"
echo ""
echo "Проверка работы:"
echo "  systemctl status mtproxy-monitor.timer"
echo "  systemctl status mtproxy-monitor-daily.timer"
echo "  journalctl -u mtproxy-monitor.service -f"
