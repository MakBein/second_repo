# xss_security_gui/breach_scenarios.py
"""
Реалистичные сценарии утечек данных для тестирования
Методы выявления и анализа реальных утечек

Использование:
- Анализ собственной инфраструктуры на утечки
- Мониторинг публичных sources (Dark Web, пастбины, etc)
- Testing и валидация detection систем
- OSINT и threat intelligence gathering
"""

import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any
from pathlib import Path


class RealBreachScenarios:
    """Генератор реалистичных сценариев утечек из реальных источников"""

    def __init__(self):
        self.scenarios = []

    # ============================================================
    # SCENARIO 1: SQL Injection → Database Dump
    # ============================================================
    def scenario_sql_injection_db_dump(self) -> Dict[str, Any]:
        """
        Сценарий: SQL Injection в /admin/users.php параметр search
        
        Техник:
        1. Обнаружение: WAF bypass через encoding, delay-based detection
        2. Exploit: UNION SELECT для извлечения schema
        3. Результат: полный dump таблицы users (email, password_hash, credit_card)
        """
        return {
            "module": "SQLi_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://example-shop.com/admin/users.php",
            "method": "POST",
            "vulnerability": "SQL Injection (Union Based)",
            "bypass_technique": "WAF bypass via hex encoding + Unicode normalization",
            "result": {
                "category": "user_data_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Полный dump таблицы users из базы данных",
                "leaked_users": [
                    {
                        "user_id": 1,
                        "email": "admin@example-shop.com",
                        "password_hash": "$2y$10$abcdefghijklmnopqrstuvwxyz1234567890",
                        "credit_card": "4111111111111111",
                        "name": "Administrator",
                        "phone": "+79991234567",
                        "address": "Moscow, Tverskaya St, 1/1"
                    },
                    {
                        "user_id": 2,
                        "email": "customer@example.com",
                        "password_hash": "$2y$10$zyxwvutsrqponmlkjihgfedcba0987654321",
                        "credit_card": "5555555555554444",
                        "name": "Ivan Petrov",
                        "phone": "+79992345678",
                        "address": "St. Petersburg, Nevsky Prospect, 10"
                    },
                    {
                        "user_id": 3,
                        "email": "merchant@shop.ru",
                        "password_hash": "$2y$10$1234567890abcdefghijklmnopqrstuvwxyz",
                        "credit_card": "4532123456789010",
                        "name": "Dmitry Sokolov",
                        "phone": "+78123456789",
                        "address": "Yekaterinburg, Lenin Avenue, 50"
                    }
                ],
                "count": 3,
                "extraction_method": "UNION-based SQLi with time-based blind fallback",
                "waf_bypasses": [
                    "Hex encoding: F52 → \\x46\\x52",
                    "Unicode normalization: ü → u + combining mark",
                    "Case variation: UnIoN → uNiOn",
                    "Comment-based obfuscation: /*!50000UNION*/",
                    "Null byte injection: UNION%00SELECT"
                ],
                "payload_example": "search=x' UNION SELECT 1,email,password_hash,credit_card,name FROM users--+",
                "difficulty": "High",
                "automation": "Automated via sqlmap with custom tamper scripts"
            }
        }

    # ============================================================
    # SCENARIO 2: Exposed .env File → SMTP /API Credentials
    # ============================================================
    def scenario_exposed_env_smtp_api(self) -> Dict[str, Any]:
        """
        Сценарий: .env файл раскрыт через Path Traversal + LFI
        
        Техник:
        1. Обнаружение: ../../.env через directory traversal
        2. LFI bypass: php://filter/convert.base64-encode/resource=.env
        3. Результат: SMTP credentials, API keys, database credentials
        """
        return {
            "module": "LFI_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://example-shop.com/document.php",
            "method": "GET",
            "vulnerability": "Local File Inclusion (LFI) + Path Traversal",
            "bypass_technique": "php://filter encoding + null byte injection + encoding stacks",
            "result": {
                "category": "email_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Извлечение конфиденциальной информации из .env",
                "email_leak": {
                    "smtp_emails": [
                        "noreply@example-shop.com",
                        "support@example-shop.com",
                        "admin@example-shop.com"
                    ],
                    "smtp_users": [
                        "noreply@example-shop.com",
                        "support@example-shop.com",
                        "admin.notifications"
                    ],
                    "smtp_passwords": [
                        "SmtpPass123!@#654",
                        "SupportEmail!Pass789",
                        "AdminNotif!Pass456"
                    ],
                    "smtp_server": "mail.example-shop.com:587",
                    "smtp_config": {
                        "server": "mail.example-shop.com",
                        "port": 587,
                        "encryption": "TLS",
                        "auth": True
                    }
                },
                "api_keys": {
                    "stripe_key": "sk_live_51H5gE2Abcdefg1234567890abcdefghijk",
                    "sendgrid_key": "SG.abcdefghijk1234567890_abcdefghijk",
                    "twilio_auth_token": "abcdefghijklmnopqrstuvwxyz123456",
                    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
                    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                },
                "database_credentials": {
                    "db_host": "db.example-shop.com",
                    "db_port": 3306,
                    "db_user": "shop_admin",
                    "db_password": "SecureDbPass789!@#",
                    "db_name": "shop_production"
                },
                "payload_example": "document.php?file=php://filter/convert.base64-encode/resource=../../../../.env",
                "waf_bypasses": [
                    "Null byte: .env%00.jpg",
                    "Encoding stacks: php://filter/convert.base64-encode/convert.quoted-printable-encode/...",
                    "Case variation: PHP://Filter",
                    "Double encoding: ..%252f..%252f.env",
                    "Ultra-long path: ../../../../../../.env (to bypass length checks)"
                ],
                "difficulty": "Medium",
                "extraction_method": "Automated LFI enumeration with php://filter wrappers"
            }
        }

    # ============================================================
    # SCENARIO 3: Password Reset Token Leakage → Account Takeover
    # ============================================================
    def scenario_password_reset_token_leak(self) -> Dict[str, Any]:
        """
        Сценарий: Password reset token утечка через referer logs
        
        Техник:
        1. Обнаружение: Weak token generation (time-based, predictable)
        2. Log leakage: Token отправлен в email, но также логируется в /logs
        3. Результат: Account takeover для multiple users
        """
        return {
            "module": "Account_Analyzer",
            "timestamp": datetime.now().isoformat(),
            "target": "https://example-shop.com/reset-password",
            "method": "GET",
            "vulnerability": "Weak password reset token + Log leakage",
            "bypass_technique": "Token prediction via brute force + timing attack",
            "result": {
                "category": "account_state_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Утечка токенов сброса пароля - возможен ATO",
                "accounts": [
                    {
                        "email": "customer1@example.com",
                        "reset_token": "a1b2c3d4e5f6g7h8i9j0_1609459200",
                        "token_valid_until": "2026-05-16T22:05:30Z",
                        "leak_source": "HTTP Referer log in /logs/access.log",
                        "exposure": "Token passed in URL query parameter, logged unencrypted"
                    },
                    {
                        "email": "merchant@shop.ru",
                        "reset_token": "b2c3d4e5f6g7h8i9j0k1_1609459201",
                        "token_valid_until": "2026-05-16T22:05:30Z",
                        "leak_source": "Email header X-Forwarded-For in server logs",
                        "exposure": "Token forwarded via proxy, visible in logs"
                    }
                ],
                "token_pattern": "Predictable: base36(timestamp) _ unix_time",
                "token_lifetime": "24 hours (too long)",
                "attack_vector": "Brute force + timing attack to predict next tokens",
                "difficulty": "Medium",
                "automation": "Automated token prediction and account takeover"
            }
        }

    # ============================================================
    # SCENARIO 4: Elasticsearch/Redis Exposed → Dump All Data
    # ============================================================
    def scenario_exposed_elasticsearch_redis(self) -> Dict[str, Any]:
        """
        Сценарий: Redis/Elasticsearch порт открыт без аутентификации
        
        Техник:
        1. Port scanning: Обнаружение открытого порта 6379 (Redis) или 9200 (ES)
        2. No auth: Прямое подключение без пароля
        3. Результат: Полный dump всех данных в памяти/индексах
        """
        return {
            "module": "Database_Leak",
            "timestamp": datetime.now().isoformat(),
            "target": "example-shop.com:6379 (Redis)",
            "method": "Direct connection",
            "vulnerability": "Exposed Redis instance without authentication",
            "bypass_technique": "No bypass needed - authentication disabled by default",
            "result": {
                "category": "user_data_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Полный dump данных из Redis (сессии, кэш, очередь)",
                "exposed_data": {
                    "session_data": {
                        "count": 1247,
                        "sample": {
                            "session_id": "abc123def456",
                            "user_id": 42,
                            "email": "user@example.com",
                            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "admin": True,
                            "expires": 1609459200
                        }
                    },
                    "cached_passwords": {
                        "count": 542,
                        "sample": "user_42:$2y$10$abcdefghijklmnopqrstuvwxyz1234567890"
                    },
                    "queued_messages": {
                        "count": 300,
                        "sample": "email_password_reset:user@example.com:token123"
                    },
                    "leaderboard": {
                        "user_scores": "visible with user_ids, emails, payment amounts"
                    }
                },
                "commands_executed": [
                    "INFO → server version, memory usage",
                    "KEYS * → enumerate all keys",
                    "HGETALL user:* → dump user data",
                    "LRANGE queue:* 0 -1 → dump message queue",
                    "DUMP key → serialize and export"
                ],
                "attack_chain": [
                    "Port scan identifying 6379",
                    "Redis-cli connection without password",
                    "Full data exfiltration via DUMP command",
                    "Local persistence (RDB snapshot)"
                ]
            }
        }

    # ============================================================
    # SCENARIO 5: Backup Files Accessible → Source Code + Secrets
    # ============================================================
    def scenario_backup_files_exposed(self) -> Dict[str, Any]:
        """
        Сценарий: Backup файлы (.bak, .zip, .tar.gz) доступны публично
        
        Техник:
        1. Обнаружение: Перебор расширений (.bak, .backup, .old, .zip)
        2. No access control: Файлы доступны через HTTP
        3. Результат: Исходный код, конфиги, credentials
        """
        return {
            "module": "Web_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://example-shop.com/",
            "method": "Directory enumeration",
            "vulnerability": "Exposed backup files with source code and secrets",
            "bypass_technique": "Simple HTTP GET with common backup extensions",
            "result": {
                "category": "user_data_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Backup архивы с исходным кодом и конфигами",
                "backup_files": {
                    "app.tar.gz": {
                        "url": "https://example-shop.com/app.tar.gz",
                        "size": "45 MB",
                        "contains": [
                            "config/database.php with credentials",
                            "config/api.php with API keys",
                            "src/auth.php with password hashing salt",
                            ".env.backup with all secrets",
                            "logs/ directory with user data",
                            "src/User.php with password reset logic (weak)"
                        ]
                    },
                    "database.sql.bak": {
                        "url": "https://example-shop.com/database.sql.bak",
                        "size": "120 MB",
                        "contains": "Full database dump with 50,000+ users",
                        "tables": ["users", "orders", "payments", "sessions", "audit_log"]
                    },
                    "admin-backup.zip": {
                        "url": "https://example-shop.com/admin-backup.zip",
                        "size": "5 MB",
                        "contains": "Admin panel source code with hardcoded credentials"
                    }
                },
                "leaked_credentials_from_backups": [
                    "Database user: shop_admin / SecureDbPass789!@#",
                    "FTP user: backup_user / FtpBackupPass123",
                    "AWS key: AKIA... / wJalrXUtnFEMI...",
                    "Stripe key: sk_live_abcdefghijk..."
                ],
                "discovered_vulnerabilities": [
                    "Weak password reset token generation",
                    "SQL injection in search parameter",
                    "Admin panel accessible via admin.example.com",
                    "Log files containing user sessions"
                ]
            }
        }

    # ============================================================
    # SCENARIO 6: Third-party API Breach → Data Exposure
    # ============================================================
    def scenario_third_party_api_breach(self) -> Dict[str, Any]:
        """
        Сценарий: Third-party API provider (email service, analytics) взломан
        
        Техник:
        1. OSINT: Обнаружение breach через Dark Web мониторинг
        2. Data correlation: Связывание данных с вашим приложением
        3. Результат: User данные из третьей стороны
        """
        return {
            "module": "Breach_Analysis",
            "timestamp": datetime.now().isoformat(),
            "target": "https://analytics-service.com (third-party)",
            "method": "OSINT / Dark Web monitoring",
            "vulnerability": "Third-party service breach",
            "bypass_technique": "N/A - External source",
            "result": {
                "category": "user_data_leak",
                "severity": "high",
                "risk": "high",
                "description": "Ваши user данные утекли через third-party analytics service",
                "breach_details": {
                    "source_service": "Analytics-Pro (analytics-service.com)",
                    "breach_date": "2026-04-15",
                    "discovery_date": "2026-05-10",
                    "affected_users": 12500,
                    "your_users_affected": 8432
                },
                "leaked_data_your_users": [
                    {
                        "email": "user@example.com",
                        "user_id": "your_app_123",
                        "analytics_id": "ga_456789",
                        "pages_visited": [
                            "/checkout",
                            "/payment",
                            "/order/12345"
                        ],
                        "conversion_data": "purchased 3 items for $45.99",
                        "ip_address": "192.168.1.100",
                        "phone": "+79991234567"
                    }
                ],
                "correlation_data": [
                    "email addresses from your app linked to analytics IDs",
                    "Customer purchase history from checkout flow",
                    "Payment amounts and credit card last 4 digits",
                    "IP addresses and device fingerprints"
                ],
                "impact": "Customer behavior tracking + payment data exposure",
                "your_responsibility": "Notify users via email/dashboard about data in third-party breach"
            }
        }

    # ============================================================
    # SCENARIO 7: GitHub Repository Leakage → Code + Secrets
    # ============================================================
    def scenario_github_repo_leak(self) -> Dict[str, Any]:
        """
        Сценарий: Private repository случайно made public
        
        Техник:
        1. OSINT: GitHub code search находит sensitive repos
        2. Git history: Клонирование repo для доступа ко всей истории (deleted files)
        3. Secrets scanning: Извлечение API keys из коммитов
        """
        return {
            "module": "Code_Leak_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://github.com/example-shop/api-server",
            "method": "GitHub public repository",
            "vulnerability": "Accidentally public private repository",
            "bypass_technique": "None - publicly accessible",
            "result": {
                "category": "user_data_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Private GitHub repo with full source code and secrets exposed",
                "repo_details": {
                    "url": "https://github.com/example-shop/api-server",
                    "visibility": "Public (was private)",
                    "commits": 1247,
                    "contributors": 5,
                    "last_commit": "2026-05-15T10:30:00Z"
                },
                "exposed_secrets_found": [
                    {
                        "type": "API_KEY",
                        "key": "sk_live_51H5gE2Abcdefg1234567890abcdefghijk",
                        "service": "Stripe",
                        "found_in": "config/stripe.js (line 42)",
                        "commit": "abc123def456 by developer@example.com"
                    },
                    {
                        "type": "DATABASE_PASSWORD",
                        "key": "SecureDbPass789!@#",
                        "database": "PostgreSQL production",
                        "found_in": ".env.example (accidentally committed)",
                        "commit": "xyz789abc123 by admin@example.com (2 months ago)"
                    },
                    {
                        "type": "OAUTH_TOKEN",
                        "key": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                        "service": "GitHub Actions",
                        "found_in": "CI/CD logs in workflow runs",
                        "access": "Full repository write access"
                    }
                ],
                "source_code_exposure": [
                    "Complete API implementation with all endpoints",
                    "User authentication logic (weak password reset)",
                    "Payment processing implementation (PCI non-compliant)",
                    "Database schema and queries (with credentials)",
                    "Admin panel implementation"
                ],
                "git_history_extraction": [
                    "Clone repo: git clone https://github.com/example-shop/api-server.git",
                    "View history: git log --all --oneline",
                    "View deleted files: git log --diff-filter=D --summary",
                    "Recover deleted files: git show HEAD~10:deleted_file.js"
                ],
                "impact": "Complete system blueprint + active credentials for all services"
            }
        }

    # ============================================================
    # SCENARIO 8: OSINT - Leaked Email Database Compilation
    # ============================================================
    def scenario_osint_email_database_compilation(self) -> Dict[str, Any]:
        """
        Сценарий: OSINT сборка утечек emailов и пароводй из multiple sources
        
        Техник:
        1. Мониторинг breaches (Have I Been Pwned, DeHashed, etc)
        2. Корреляция данных (email address matching)
        3. Результат: Списки email/password для brute force или phishing
        """
        return {
            "module": "Contact_Leak",
            "timestamp": datetime.now().isoformat(),
            "target": "Multiple sources (OSINT)",
            "method": "Data aggregation from public breaches",
            "vulnerability": "Email addresses in public breach databases",
            "bypass_technique": "OSINT - no bypass needed (public data)",
            "result": {
                "category": "email_leak",
                "severity": "high",
                "risk": "high",
                "description": "Email адреса ваших users найдены в публичных breach databases",
                "osint_sources": [
                    "Have I Been Pwned (HIBP) API",
                    "DeHashed dark web breach database",
                    "Leaked LinkedIn credentials (750M+ users)",
                    "Twitter email dumps",
                    "Previous ecommerce breaches (Equifax, Target, etc)"
                ],
                "your_users_found": 3247,
                "sample_matches": [
                    {
                        "email": "customer1@example.com",
                        "password_hash": "$2y$10$abcdefghijklmnopqrstuvwxyz1234567890",
                        "password_plain": "Summer2021!",
                        "source_breach": "LinkedIn 2021 leak",
                        "risk": "Customer might reuse password"
                    },
                    {
                        "email": "merchant@shop.ru",
                        "password_plain": "123456",
                        "source_breach": "Adobe 2013 breach",
                        "risk": "Weak password - easily guessable"
                    }
                ],
                "statistics": {
                    "emails_in_known_breaches": 3247,
                    "weak_passwords": 1247,
                    "reused_passwords": 892,
                    "accounts_at_risk": 2450
                },
                "recommended_actions": [
                    "Email affected users with breach notification",
                    "Force password reset for compromised email/password combinations",
                    "Implement HIBP API check on user registration",
                    "Monitor for credential stuffing attacks"
                ]
            }
        }

    # ============================================================
    # SCENARIO 9: Mobile App API Interception → User Data
    # ============================================================
    def scenario_mobile_app_api_interception(self) -> Dict[str, Any]:
        """
        Сценарий: Мобильное приложение отправляет данные по HTTP или с weak TLS
        
        Техник:
        1. MITM: Перехват трафика через frida/burp на jailbroken device
        2. No certificate pinning: SSL можно обойти
        3. Результат: User сессии, API keys, personal data
        """
        return {
            "module": "Mobile_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://api.example-shop.com/mobile/",
            "method": "API traffic interception (MITM)",
            "vulnerability": "Weak TLS + no certificate pinning + sensitive data in transit",
            "bypass_technique": "Frida/Burp proxy + custom CA certificate on jailbroken device",
            "result": {
                "category": "user_data_leak",
                "severity": "high",
                "risk": "high",
                "description": "Перехвачены API запросы мобильного приложения с user data",
                "intercepted_requests": [
                    {
                        "method": "POST",
                        "endpoint": "/api/v1/auth/login",
                        "request_body": {
                            "email": "user@example.com",
                            "password": "PlainPasswordNotHashed!",
                            "device_fingerprint": "abc123xyz789"
                        },
                        "response": {
                            "user_id": 42,
                            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "refresh_token": "refresh_abc123def456",
                            "user_email": "user@example.com",
                            "user_phone": "+79991234567"
                        }
                    },
                    {
                        "method": "GET",
                        "endpoint": "/api/v1/users/profile",
                        "headers": {
                            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                        },
                        "response": {
                            "user_id": 42,
                            "email": "user@example.com",
                            "phone": "+79991234567",
                            "address": "Moscow, Tverskaya St, 1/1",
                            "credit_cards": [
                                {
                                    "last4": "1111",
                                    "expiry": "12/25",
                                    "is_default": True
                                }
                            ]
                        }
                    },
                    {
                        "method": "POST",
                        "endpoint": "/api/v1/orders",
                        "response": {
                            "order_id": 12345,
                            "items": [...],
                            "total": 149.99,
                            "payment_method": "card_ending_1111",
                            "shipping_address": "Moscow, Tverskaya St, 1/1"
                        }
                    }
                ],
                "vulnerabilities_found": [
                    "Password sent in plain text in JSON body (should be HTTPS only + hashing)",
                    "Auth tokens in Bearer header without expiration check",
                    "Sensitive user data (phone, address) in response without field-level encryption",
                    "Credit card last 4 digits exposed (PCI violation)",
                    "No request signing - easy to forge requests"
                ],
                "attack_capability": [
                    "Account takeover using auth tokens",
                    "Enumerate user data",
                    "Place orders on behalf of users",
                    "Extract credit card data",
                    "Phishing via email/phone from intercepted data"
                ]
            }
        }

    # ============================================================
    # SCENARIO 10: Cloud Misconfiguration → Public S3 Bucket
    # ============================================================
    def scenario_cloud_storage_misconfiguration(self) -> Dict[str, Any]:
        """
        Сценарий: AWS S3 bucket или Azure Blob Storage с public access
        
        Техник:
        1. S3 enumeration: Перебор common bucket names
        2. Listing: AWS allows bucket listing если неправильно configured
        3. Результат: User uploads, documents, export data
        """
        return {
            "module": "Cloud_Scanner",
            "timestamp": datetime.now().isoformat(),
            "target": "https://example-shop-backups.s3.amazonaws.com/",
            "method": "AWS S3 misconfiguration",
            "vulnerability": "Public S3 bucket with List permission enabled",
            "bypass_technique": "S3 enumeration via direct URL + AWS CLI listing",
            "result": {
                "category": "user_data_leak",
                "severity": "critical",
                "risk": "critical",
                "description": "Public S3 bucket с user data, invoices, и backups",
                "bucket_details": {
                    "name": "example-shop-backups",
                    "region": "us-east-1",
                    "public_access": True,
                    "list_enabled": True,
                    "files_found": 1247
                },
                "exposed_files": [
                    {
                        "name": "user-exports/2026-05-15/users_backup.csv",
                        "size": "45 MB",
                        "modified": "2026-05-15T10:00:00Z",
                        "type": "CSV with emails, passwords (hashed), addresses, phones"
                    },
                    {
                        "name": "invoices/2026/*/invoice-*.pdf",
                        "count": 5432,
                        "type": "User invoices with credit card masks and billing addresses"
                    },
                    {
                        "name": "database-backups/daily/dump-2026-05-15.sql.gz",
                        "size": "250 MB",
                        "type": "Full database dump with all user data"
                    },
                    {
                        "name": "analytics/user-behavior-2026-05.csv",
                        "size": "120 MB",
                        "type": "User behavior analysis with emails linked to activity"
                    },
                    {
                        "name": "reports/sensitive/admin-reports-2026.xlsx",
                        "type": "Financial reports with customer data"
                    }
                ],
                "enumeration_command": [
                    "aws s3 ls s3://example-shop-backups/ --recursive",
                    "aws s3 cp s3://example-shop-backups/users_backup.csv .",
                    "for file in $(aws s3 ls s3://example-shop-backups/invoices/2026/05/ | awk '{print $NF}'); do aws s3 cp s3://example-shop-backups/invoices/2026/05/$file .; done"
                ],
                "impact": "Complete user database + financial records + behavioral data exposed"
            }
        }

    def generate_all_scenarios(self) -> List[Dict[str, Any]]:
        """Генерирует все 10 сценариев утечек"""
        return [
            self.scenario_sql_injection_db_dump(),
            self.scenario_exposed_env_smtp_api(),
            self.scenario_password_reset_token_leak(),
            self.scenario_exposed_elasticsearch_redis(),
            self.scenario_backup_files_exposed(),
            self.scenario_third_party_api_breach(),
            self.scenario_github_repo_leak(),
            self.scenario_osint_email_database_compilation(),
            self.scenario_mobile_app_api_interception(),
            self.scenario_cloud_storage_misconfiguration(),
        ]


def save_real_breach_scenarios(output_file: str = None) -> str:
    """
    Сохраняет реалистичные сценарии утечек в JSON файл
    
    :param output_file: Path to output file (default: xss_security_gui/logs/real_breaches.json)
    :return: Path to saved file
    """
    if output_file is None:
        output_file = Path(__file__).parent / "logs" / "real_breaches.json"
    else:
        output_file = Path(output_file)
    
    output_file.parent.mkdir(exist_ok=True, parents=True)
    
    generator = RealBreachScenarios()
    scenarios = generator.generate_all_scenarios()
    
    data = {
        "total": len(scenarios),
        "generated": datetime.now().isoformat(),
        "description": "Реалистичные сценарии утечек данных для тестирования",
        "warning": "ДЛЯ ТЕСТИРОВАНИЯ БЕЗОПАСНОСТИ ТОЛЬКО! Используйте только на своих системах.",
        "scenarios": scenarios
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    
    print(f"[✅] {len(scenarios)} сценариев утечек сохранено в: {output_file}")
    return str(output_file)


if __name__ == '__main__':
    # Генерируем все сценарии и сохраняем
    file_path = save_real_breach_scenarios()
    
    print(f"\n[📊] Сценарии утечек:")
    generator = RealBreachScenarios()
    for i, scenario in enumerate(generator.generate_all_scenarios(), 1):
        print(f"  {i}. {scenario['vulnerability']} → {scenario['result']['category']}")
    
    print(f"\n[💾] Файл: {file_path}")
    print(f"\n[📝] Для интеграции с threat_tab используйте:")
    print(f"   from xss_security_gui.threat_data_loader import load_threat_data_to_gui")
    print(f"   from xss_security_gui.breach_scenarios import save_real_breach_scenarios")
    print(f"   save_real_breach_scenarios()")

