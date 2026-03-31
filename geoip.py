import logging
import sqlite3
import time
import requests
from typing import List, Dict

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days

def init_geo_db(conn: sqlite3.Connection):
    """
    Initializes the cache table for IP geolocation within the provided SQLite connection.
    """
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_geo_cache (
            ip TEXT PRIMARY KEY,
            data TEXT,
            timestamp INTEGER
        )
    ''')
    conn.commit()

def get_ips_geo_info(ips: List[str], db_conn: sqlite3.Connection) -> Dict[str, str]:
    """
    Takes a list of IP addresses and returns a dictionary: {ip: "(City, ISP)"}.
    First checks the local SQLite cache cache. For missing or expired IPs,
    queries the ip-api.com batch API.
    """
    result = {}
    if not ips:
        return result
    
    unique_ips = list(set(ips))
    current_time = int(time.time())
    ips_to_fetch = []
    
    cursor = db_conn.cursor()
    
    # Check cache
    for ip in unique_ips:
        cursor.execute("SELECT data, timestamp FROM ip_geo_cache WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        
        if row:
            data, timestamp = row
            if data.startswith('{'):
                import json
                try:
                    jd = json.loads(data)
                    data = f" ({jd.get('city', 'Unknown City')}, {jd.get('isp', 'Unknown ISP')})"
                except Exception:
                    pass
            
            if (current_time - timestamp) <= CACHE_TTL_SECONDS:
                result[ip] = data
                continue
        
        ips_to_fetch.append(ip)
            
    if not ips_to_fetch:
        return result
        
    # Fetch from API for remaining IPs
    # ip-api.com batch API limit is 100 IPs per request
    for i in range(0, len(ips_to_fetch), 100):
        batch = ips_to_fetch[i:i + 100]
        try:
            url = "http://ip-api.com/batch?fields=query,city,isp,status"
            response = requests.post(url, json=batch, timeout=10)
            
            if response.status_code == 200:
                api_data = response.json()
                for item in api_data:
                    ip = item.get("query")
                    if not ip:
                        continue
                        
                    if item.get("status") == "success":
                        city = item.get("city", "Unknown City")
                        isp = item.get("isp", "Unknown ISP")
                        geo_str = f" ({city}, {isp})"
                        
                        cursor.execute(
                            "INSERT OR REPLACE INTO ip_geo_cache (ip, data, timestamp) VALUES (?, ?, ?)",
                            (ip, geo_str, current_time)
                        )
                        result[ip] = geo_str
                    else:
                        logger.warning(f"Failed to get geo info for {ip}: {item}")
                        result[ip] = ""
            else:
                logger.error(f"IP-API request failed with status {response.status_code}")
                for ip in batch:
                    result[ip] = ""
                    
        except Exception as e:
            logger.error(f"Failed to fetch geo info for batch: {e}")
            for ip in batch:
                result[ip] = ""
                
    db_conn.commit()
    return result
