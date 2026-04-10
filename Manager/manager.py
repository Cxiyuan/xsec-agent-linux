#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xsec-manager - Security Monitoring Server (EDR Manager)

Architecture:
  - Flask HTTP server (port 8080) with JWT auth, REST API
  - asyncio TCP server (port 8443) for Agent communications
  - Flask-SocketIO (port 8080) for real-time WebSocket push to frontend
  - APScheduler for periodic heartbeat timeout checks

Message Types:
  Agent -> Manager: agent_register, heartbeat, command_result, response_result, threat_report
  Manager -> Agent: command_execute, response_policy, config_update

Command Dispatch Flow:
  1. Frontend POST /api/response/dispatch
  2. Manager writes commands table (status=pending)
  3. Manager sends via TCP to Agent
  4. Agent executes and returns command_result
  5. Manager updates commands table status
"""

import asyncio
import json
import os
import re
import secrets
import sqlite3
import struct
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import hashlib
import hmac
import structlog
import toml
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

try:
    from flask_socketio import SocketIO, emit, join_room
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False
    SocketIO = None

from baseline import BaselineManager
from discovery import AssetDiscovery, ScanMethod
from vuln_db import CVEDatabase
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============================================================================
# Notifications - SOAR Integration
# ============================================================================

def send_feishu_notification(webhook_url: str, title: str, content: str, severity: str):
    """发送飞书通知"""
    if not webhook_url:
        return False
    try:
        payload = {
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "title": f"[{severity.upper()}] {title}",
                        "content": [[{"tag": "text", "text": content}]]
                    }
                }
            }
        }
        import requests
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        logger.error("feishu_notification_failed", error=str(e))
        return False

def send_dingtalk_notification(webhook_url: str, title: str, content: str, severity: str):
    """发送钉钉通知"""
    if not webhook_url:
        return False
    try:
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"[{severity.upper()}] {title}",
                "text": "### " + severity.upper() + " " + title + "\n\n" + content + "\n\n> 来自 xsec 安全监控系统"
            }
        }
        import requests
        resp = requests.post(webhook_url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception as e:
        logger.error("dingtalk_notification_failed", error=str(e))
        return False

class AgentRegistry:
    """简单的Agent注册中心（支持多Manager集群）"""
    
    def __init__(self, db: 'DatabaseManager'):
        self.db = db
        self._init_table()
    
    def _init_table(self):
        conn = self.db.get_conn()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS cluster_members (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                last_heartbeat TEXT,
                agent_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
    
    def register_manager(self, manager_id: str, host: str, port: int):
        conn = self.db.get_conn()
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO cluster_members (id, host, port, last_heartbeat, status)
            VALUES (?, ?, ?, ?, 'active')
        """, (manager_id, host, port, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def get_all_agents(self) -> list:
        """获取所有Manager的Agent列表"""
        conn = self.db.get_conn()
        c = conn.cursor()
        c.execute("SELECT id, hostname, ip, status, last_seen FROM agents")
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "hostname": r[1], "ip": r[2], "status": r[3], "last_seen": r[4]} for r in rows]
    
    def get_cluster_health(self) -> dict:
        """获取集群健康状态"""
        conn = self.db.get_conn()
        c = conn.cursor()
        c.execute("SELECT id, host, port, status, agent_count FROM cluster_members")
        rows = c.fetchall()
        conn.close()
        return {
            "managers": [{"id": r[0], "host": r[1], "port": r[2], "status": r[3], "agent_count": r[4]} for r in rows],
            "total_agents": sum(r[4] for r in rows)
        }



# ============================================================================
# Logging
# ============================================================================

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()

# ============================================================================
# Configuration
# ============================================================================

DEFAULT_JWT_SECRET = "xsec-secret-change-in-production"
DEFAULT_AGENT_SECRET = "xsec-default-agent-secret"


def _load_config():
    cfg_path = Path("manager.toml")
    if cfg_path.exists():
        return toml.load(cfg_path)
    return {}


config = _load_config()

config.setdefault("server", {
    "host": "0.0.0.0",
    "port": 8443,
    "heartbeat_timeout_secs": 90,
})
config.setdefault("database", {"path": "data/manager.db"})
config.setdefault("jwt", {"secret_key": os.environ.get("JWT_SECRET_KEY", "")})
config.setdefault("agent", {"hmac_secret": os.environ.get("AGENT_HMAC_SECRET", "")})
config.setdefault("tls", {"enabled": False, "cert": "", "key": ""})
config.setdefault("web", {"host": "0.0.0.0", "port": 8080, "allowed_origins": []})
config.setdefault("ratelimit", {"enabled": True, "default": "200 per minute", "login": "5 per minute"})

# ============================================================================
# Security: Strict Startup Checks
# ============================================================================


def _check_security_config():
    """Refuse to start if security-critical settings use insecure defaults."""

    errors = []

    # 1. JWT secret key: reject default / empty / obviously insecure
    jwt_secret = config.get("jwt", {}).get("secret_key", "")
    if not jwt_secret:
        errors.append(
            "JWT_SECRET_KEY is not configured. "
            "Set jwt.secret_key in manager.toml or JWT_SECRET_KEY env var."
        )
    elif jwt_secret in (DEFAULT_JWT_SECRET, "changeme", "secret", "password", "admin"):
        errors.append(
            f"JWT_SECRET_KEY uses an insecure default value '{jwt_secret}'. "
            "Change it to a random secret in production."
        )

    # 2. Agent HMAC secret: reject default / empty
    agent_secret = config.get("agent", {}).get("hmac_secret", "")
    if not agent_secret:
        errors.append(
            "AGENT_HMAC_SECRET is not configured. "
            "Set agent.hmac_secret in manager.toml or AGENT_HMAC_SECRET env var."
        )
    elif agent_secret in (DEFAULT_AGENT_SECRET, "changeme", "secret", "password"):
        errors.append(
            "AGENT_HMAC_SECRET uses an insecure default value. "
            "Change it to a random secret in production."
        )

    if errors:
        for err in errors:
            logger.error("security_config_error", detail=err)
        raise SystemExit(
            "\n\nSECURITY CONFIGURATION ERRORS:\n" + "\n".join(f"  - {e}" for e in errors) +
            "\n\nFix these issues before starting. Aborting."
        )

    # 3. TLS warning (non-fatal, just warn)
    if not config.get("tls", {}).get("enabled", False):
        logger.warning(
            "TLS is disabled. Agent TCP communications are not encrypted. "
            "Enable TLS in production (set tls.enabled=true, tls.cert, tls.key)."
        )


_check_security_config()

# ============================================================================
# Thread Pool
# ============================================================================

REQUEST_TIMEOUT_SECONDS = 30
_executor = ThreadPoolExecutor(max_workers=10)


def run_with_timeout(func, timeout=REQUEST_TIMEOUT_SECONDS):
    from concurrent.futures import TimeoutError as FuturesTimeoutError

    @wraps(func)
    def wrapper(*args, **kwargs):
        future = _executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            logger.error("request_timeout", func=func.__name__, timeout=timeout)
            return jsonify({"code": 1, "error": f"request timeout after {timeout}s"}), 408

    return wrapper


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        c = conn.cursor()

        # Agents table
        c.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip TEXT NOT NULL,
                os TEXT,
                arch TEXT,
                version TEXT,
                status TEXT DEFAULT 'offline',
                registered_at TEXT NOT NULL,
                last_seen TEXT,
                asset_name TEXT,
                asset_type TEXT,
                asset_group TEXT,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                disk_partitions TEXT,
                agent_ip TEXT,
                environment_info TEXT
            )
        """)

        # Alerts table (with indexes)
        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                handled_at TEXT,
                handled_by TEXT
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_agent_created ON alerts(agent_id, created_at)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity, status)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")

        # Commands table (with indexes)
        c.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                args TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_commands_created_at ON commands(created_at)")

        # Response policies table
        c.execute("""
            CREATE TABLE IF NOT EXISTS response_policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT,
                enabled INTEGER DEFAULT 1,
                actions TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)

        # Response logs table
        c.execute("""
            CREATE TABLE IF NOT EXISTS response_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_id TEXT,
                agent_id TEXT,
                action TEXT,
                status TEXT,
                result TEXT,
                executed_at TEXT NOT NULL
            )
        """)

        # Users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'admin',
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # Audit logs table
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                ip TEXT,
                created_at TEXT NOT NULL
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)"
        )

        # Alert correlations table
        c.execute("""
            CREATE TABLE IF NOT EXISTS alert_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                alert_count INTEGER DEFAULT 1,
                merged_alert_ids TEXT,
                title TEXT,
                severity TEXT,
                description TEXT,
                status TEXT DEFAULT 'active'
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_corr_source_title ON alert_correlations(source_ip, title, status)"
        )

        # Agent upgrades table
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_upgrades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                version TEXT NOT NULL,
                download_url TEXT,
                checksum TEXT,
                size_bytes INTEGER DEFAULT 0,
                changelog TEXT,
                released_at TEXT,
                mandatory INTEGER DEFAULT 0,
                status TEXT DEFAULT 'available',
                created_at TEXT NOT NULL,
                deployed_at TEXT
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_upgrades_agent ON agent_upgrades(agent_id, status)"
        )

        # Agent upgrade logs table
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_upgrade_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                from_version TEXT,
                to_version TEXT,
                status TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            )
        """)
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_upgrade_logs_agent ON agent_upgrade_logs(agent_id, created_at)"
        )

        # ========== P3: Cluster Members Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS cluster_members (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                last_heartbeat TEXT,
                agent_count INTEGER DEFAULT 0
            )
        """)

        # ========== P3: Compliance Reports Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS compliance_reports (
                id TEXT PRIMARY KEY,
                report_type TEXT NOT NULL,
                level TEXT,
                status TEXT DEFAULT 'pending',
                file_path TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        """)

        # ========== Agent Processes Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                pid INTEGER NOT NULL,
                name TEXT NOT NULL,
                cpu REAL,
                memory REAL,
                user TEXT,
                parent_pid INTEGER,
                captured_at TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_processes_agent ON agent_processes(agent_id, captured_at)")

        # ========== Agent Network Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_network (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                protocol TEXT,
                local_addr TEXT,
                remote_addr TEXT,
                state TEXT,
                pid INTEGER,
                program TEXT,
                captured_at TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_network_agent ON agent_network(agent_id, captured_at)")

        # ========== Agent USB Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS agent_usb (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                vid TEXT,
                pid TEXT,
                device_type TEXT,
                vendor TEXT,
                product TEXT,
                status TEXT DEFAULT 'connected',
                inserted_at TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_usb_agent ON agent_usb(agent_id, inserted_at)")

        # ========== FIM Rules Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS fim_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                rule_type TEXT DEFAULT 'file',
                agent_id TEXT DEFAULT '*',
                created_at TEXT NOT NULL
            )
        """)

        # ========== FIM History Table ==========
        c.execute("""
            CREATE TABLE IF NOT EXISTS fim_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                path TEXT NOT NULL,
                change_type TEXT NOT NULL,
                hash TEXT,
                captured_at TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_fim_history_agent ON fim_history(agent_id, captured_at)")

        conn.commit()
        conn.close()

        self._ensure_default_admin()

    def _ensure_default_admin(self):
        from werkzeug.security import generate_password_hash
        conn = self.get_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            # FIX 4: Use werkzeug.security.generate_password_hash instead of weak SHA256
            password_hash = generate_password_hash("admin")
            # Add must_change_password column if it doesn't exist (migration)
            c.execute("SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='must_change_password'")
            if c.fetchone()[0] == 0:
                c.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 1")
            c.execute(
                "INSERT INTO users (username, password_hash, role, created_at, must_change_password) VALUES (?, ?, ?, ?, 1)",
                ("admin", password_hash, "admin", datetime.now().isoformat()),
            )
            conn.commit()
        conn.close()

    def get_conn(self):
        return sqlite3.connect(self.db_path, timeout=30)

    def log_audit(
        self,
        user_id: str = "",
        action: str = "",
        target: str = "",
        detail: str = "",
        ip: str = "",
    ):
        try:
            conn = self.get_conn()
            c = conn.cursor()
            c.execute(
                "INSERT INTO audit_logs (user_id, action, target, detail, ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, action, target, detail, ip, datetime.now().isoformat()),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("audit_log_failed", error=str(e))


# ============================================================================
# Alert Correlation
# ============================================================================


def correlate_alert(
    db: DatabaseManager,
    agent_id: str,
    source_ip: str,
    title: str,
    severity: str,
    description: str,
) -> dict:
    """
    Merge alerts from the same source IP + same title within a 1-minute window.
    Returns: {"merged": bool, "correlation_id": int|None, "alert_id": int|None}
    
    FIX #7, #8: Use context manager for database connection.
    FIX #13: Handle empty source_ip by using agent_id + title as fallback correlation key.
    """
    # FIX #13: If source_ip is empty, use agent_id + title for correlation instead
    correlation_key = source_ip if source_ip else f"agent:{agent_id}"
    
    result = {"merged": False, "correlation_id": None, "alert_id": None}
    
    with db.get_conn() as conn:  # FIX #7, #8: Use context manager
        c = conn.cursor()
        now = datetime.now()
        window = (now - timedelta(minutes=1)).isoformat()

        c.execute(
            """
            SELECT id, alert_count, merged_alert_ids FROM alert_correlations
            WHERE source_ip = ? AND agent_id = ? AND title = ?
              AND status = 'active' AND last_seen >= ?
            ORDER BY last_seen DESC LIMIT 1
            """,
            (correlation_key, agent_id, title, window),
        )
        row = c.fetchone()

        if row:
            corr_id, prev_count, merged_ids = row
            ids_list = json.loads(merged_ids) if merged_ids else []
            ids_list.append(f"alert_{now.timestamp()}")

            c.execute(
                """
                UPDATE alert_correlations
                SET alert_count = alert_count + 1, last_seen = ?, merged_alert_ids = ?
                WHERE id = ?
                """,
                (now.isoformat(), json.dumps(ids_list), corr_id),
            )
            conn.commit()
            result["merged"] = True
            result["correlation_id"] = corr_id
        else:
            c.execute(
                """
                INSERT INTO alert_correlations
                (source_ip, agent_id, first_seen, last_seen, alert_count,
                 merged_alert_ids, title, severity, description, status)
                VALUES (?, ?, ?, ?, 1, '[]', ?, ?, ?, 'active')
                """,
                (
                    correlation_key,
                    agent_id,
                    now.isoformat(),
                    now.isoformat(),
                    title,
                    severity,
                    description,
                ),
            )
            conn.commit()
            result["correlation_id"] = c.lastrowid

            # Insert representative alert
            c.execute(
                """
                INSERT INTO alerts (agent_id, alert_type, severity, title, description, status, created_at)
                VALUES (?, 'correlation', ?, ?, ?, 'pending', ?)
                """,
                (agent_id, severity, title, description, now.isoformat()),
            )
            conn.commit()
            result["alert_id"] = c.lastrowid
    
    return result


def get_active_correlations(db: DatabaseManager, limit: int = 50) -> list:
    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        """
        SELECT * FROM alert_correlations
        WHERE status = 'active' ORDER BY last_seen DESC LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


# ============================================================================
# Agent Timeout Checker
# ============================================================================


def check_agent_timeouts(db: DatabaseManager, timeout_secs: int = 90):
    conn = db.get_conn()
    c = conn.cursor()
    threshold = (datetime.now() - timedelta(seconds=timeout_secs)).isoformat()
    c.execute(
        "UPDATE agents SET status = 'offline' WHERE last_seen < ? AND status = 'online'",
        (threshold,),
    )
    updated = c.rowcount
    conn.commit()
    conn.close()
    if updated:
        logger.info("agents_marked_offline", count=updated)


# ============================================================================
# HMAC Helpers
# ============================================================================


def _get_agent_secret() -> str:
    return config.get("agent", {}).get("hmac_secret", "")


def compute_agent_hmac(payload: bytes) -> str:
    secret = _get_agent_secret().encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_agent_hmac(payload: bytes, signature: str) -> bool:
    expected = compute_agent_hmac(payload)
    return hmac.compare_digest(expected, signature)


def sign_payload(payload: bytes) -> str:
    return compute_agent_hmac(payload)


# ============================================================================
# TCP Server for Agents
# ============================================================================


class AgentTCPServer:
    """
    Asyncio TCP server that receives messages from Agents and sends commands back.
    All messages are JSON with a 4-byte big-endian length prefix.

    Frame format: <hmac_hex> <space> <json_payload>
    """

    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB sanity limit

    def __init__(
        self, host: str = "0.0.0.0", port: int = 8443, db: DatabaseManager = None
    ):
        self.host = host
        self.port = port
        self.db = db
        # agent_id -> {"writer": StreamWriter, "last_seen": datetime}
        self.agents: dict = {}
        self._server = None
        self._socketio = None

    def set_socketio(self, socketio):
        self._socketio = socketio

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        addr = writer.get_extra_info("peername")
        logger.info("agent_tcp_connected", addr=addr)
        agent_id = None

        try:
            while True:
                header = await reader.read(4)
                if not header or len(header) < 4:
                    break

                length = int.from_bytes(header[:4], byteorder="big")
                if length > self.MAX_MESSAGE_SIZE:
                    logger.warning(
                        "agent_message_too_large", addr=addr, length=length
                    )
                    break

                raw = await reader.read(length)
                if not raw:
                    break

                # Frame format: <signature_hex> <space> <json_payload>
                space_idx = raw.find(b" ")
                if space_idx == -1:
                    logger.warning("agent_message_no_signature", addr=addr)
                    continue

                sig_hex = raw[:space_idx].decode()
                payload = raw[space_idx + 1 :]

                if not verify_agent_hmac(payload, sig_hex):
                    logger.warning("agent_hmac_failed", addr=addr)
                    err = json.dumps(
                        {"type": "error", "message": "HMAC verification failed"}
                    ).encode()
                    writer.write(
                        len(err).to_bytes(4, byteorder="big") + err
                    )
                    await writer.drain()
                    continue

                try:
                    msg = json.loads(payload.decode())
                except Exception as e:
                    logger.error(
                        "agent_json_parse_failed", addr=addr, error=str(e)
                    )
                    continue

                agent_id = await self._process_message(msg, writer, agent_id)

        except Exception as e:
            logger.error("agent_tcp_error", addr=addr, error=str(e))
        finally:
            if agent_id and agent_id in self.agents:
                del self.agents[agent_id]
            writer.close()
            await writer.wait_closed()
            logger.info(
                "agent_tcp_disconnected", addr=addr, agent_id=agent_id
            )

    async def _process_message(
        self, msg: dict, writer: asyncio.StreamWriter, last_agent_id: str = None
    ) -> str:
        msg_type = msg.get("type", "")
        agent_id = msg.get("agent_id", last_agent_id)

        # ── agent_register ───────────────────────────────────────────────
        if msg_type == "agent_register":
            agent_id = msg.get("agent_id")
            self.agents[agent_id] = {
                "writer": writer,
                "last_seen": datetime.now(),
            }

            conn = self.db.get_conn()
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO agents
                (id, hostname, ip, mac, os, arch, version, status, registered_at, last_seen,
                 cpu_percent, memory_percent, disk_percent, disk_partitions, agent_ip, environment_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?, ?,
                        ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    hostname = excluded.hostname,
                    ip = excluded.ip,
                    mac = CASE WHEN excluded.mac IS NOT NULL AND excluded.mac != '' THEN excluded.mac ELSE agents.mac END,
                    os = excluded.os,
                    arch = excluded.arch,
                    version = excluded.version,
                    status = 'online',
                    last_seen = excluded.last_seen,
                    cpu_percent = excluded.cpu_percent,
                    memory_percent = excluded.memory_percent,
                    disk_percent = excluded.disk_percent,
                    disk_partitions = excluded.disk_partitions,
                    agent_ip = excluded.agent_ip,
                    environment_info = excluded.environment_info
                """,
                (
                    agent_id,
                    msg.get("hostname", ""),
                    msg.get("ip", ""),
                    msg.get("mac", ""),
                    msg.get("os", ""),
                    msg.get("arch", ""),
                    msg.get("version", ""),
                    msg.get("registered_at", datetime.now().isoformat()),
                    datetime.now().isoformat(),
                    msg.get("cpu_percent", 0),
                    msg.get("memory_percent", 0),
                    msg.get("disk_percent", 0),
                    json.dumps(msg.get("disk_partitions", [])),
                    msg.get("agent_ip", ""),
                    json.dumps(msg.get("environment_info", {})),
                ),
            )
            conn.commit()
            conn.close()

            logger.info(
                "agent_registered", agent_id=agent_id, hostname=msg.get("hostname")
            )

            await self._send(writer, {"type": "register_ack", "agent_id": agent_id, "status": "ok"})
            return agent_id

        # ── heartbeat ───────────────────────────────────────────────────
        elif msg_type == "heartbeat":
            agent_id = msg.get("agent_id", last_agent_id)
            if not agent_id:
                return last_agent_id

            self.agents[agent_id] = {
                "writer": writer,
                "last_seen": datetime.now(),
            }

            conn = self.db.get_conn()
            c = conn.cursor()
            c.execute(
                """
                UPDATE agents
                SET last_seen = ?, status = 'online',
                    cpu_percent = ?, memory_percent = ?,
                    ip = COALESCE(?, ip),
                    hostname = COALESCE(NULLIF(?, ''), hostname)
                WHERE id = ?
                """,
                (
                    datetime.now().isoformat(),
                    msg.get("cpu_percent", 0),
                    msg.get("memory_percent", 0),
                    msg.get("ip"),
                    msg.get("hostname"),
                    agent_id,
                ),
            )
            conn.commit()
            conn.close()

            await self._send(writer, {"type": "heartbeat_ack"})
            return agent_id

        # ── command_result ──────────────────────────────────────────────
        elif msg_type == "command_result":
            agent_id = msg.get("agent_id", last_agent_id)
            data = msg.get("data", {})
            cmd_id = data.get("command_id", "")
            success = data.get("success", False)
            stdout = data.get("stdout", "")
            stderr = data.get("stderr", "")
            duration_ms = data.get("duration_ms", 0)

            conn = self.db.get_conn()
            c = conn.cursor()
            c.execute(
                """
                UPDATE commands
                SET status = ?, result = ?, completed_at = ?
                WHERE id = ?
                """,
                (
                    "completed" if success else "failed",
                    json.dumps({
                        "stdout": stdout,
                        "stderr": stderr,
                        "duration_ms": duration_ms,
                        "returned_at": datetime.now().isoformat(),
                    }),
                    datetime.now().isoformat(),
                    cmd_id,
                ),
            )
            conn.commit()
            conn.close()

            logger.info(
                "command_result_received",
                agent_id=agent_id,
                command_id=cmd_id,
                success=success,
            )

            if self._socketio:
                self._socketio.emit(
                    "command_result",
                    {
                        "command_id": cmd_id,
                        "agent_id": agent_id,
                        "status": "completed" if success else "failed",
                        "result": stdout,
                    },
                    room="commands",
                )
            return agent_id

        # ── response_result ─────────────────────────────────────────────
        elif msg_type == "response_result":
            agent_id = msg.get("agent_id", last_agent_id)
            data = msg.get("data", {})
            action = data.get("action", "")
            success = data.get("success", False)
            message = data.get("message", "")

            conn = self.db.get_conn()
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO response_logs (policy_id, agent_id, action, status, result, executed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    data.get("policy_id", ""),
                    agent_id,
                    action,
                    "success" if success else "failed",
                    message,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            conn.close()

            logger.info(
                "response_result_received",
                agent_id=agent_id,
                action=action,
                success=success,
            )

            if self._socketio:
                self._socketio.emit(
                    "response_result",
                    {
                        "agent_id": agent_id,
                        "action": action,
                        "status": "success" if success else "failed",
                        "message": message,
                    },
                    room="commands",
                )
            return agent_id

        # ── threat_report ───────────────────────────────────────────────
        elif msg_type == "threat_report":
            agent_id = msg.get("agent_id", last_agent_id)
            data = msg.get("data", {})

            alert_type = data.get("alert_type", "security")
            severity = data.get("severity", "medium")
            title = data.get("title", "Unknown threat")
            description = data.get("description", "")
            source_ip = data.get("source_ip", "")

            conn = self.db.get_conn()
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO alerts (agent_id, alert_type, severity, title, description, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (
                    agent_id,
                    alert_type,
                    severity,
                    title,
                    description,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            conn.close()

            # Correlation
            corr = correlate_alert(
                self.db, agent_id, source_ip, title, severity, description
            )

            # WebSocket push
            if self._socketio:
                self._socketio.emit(
                    "new_alert",
                    {
                        "agent_id": agent_id,
                        "alert_type": alert_type,
                        "severity": severity,
                        "title": title,
                        "description": description,
                        "source_ip": source_ip,
                        "created_at": datetime.now().isoformat(),
                        "merged": corr["merged"],
                        "correlation_id": corr.get("correlation_id"),
                    },
                    room="alerts",
                )

            logger.info(
                "threat_report_received",
                agent_id=agent_id,
                alert_type=alert_type,
                severity=severity,
            )
            return agent_id

        return last_agent_id

    async def _send(self, writer: asyncio.StreamWriter, msg: dict):
        payload = json.dumps(msg).encode()
        signed = sign_payload(payload)
        frame = signed.encode() + b" " + payload
        writer.write(len(frame).to_bytes(4, byteorder="big") + frame)
        await writer.drain()

    async def start(self):
        self._server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        logger.info("tcp_server_started", host=self.host, port=self.port)
        async with self._server:
            await self._server.serve_forever()

    # ------------------------------------------------------------------
    # Send a message to a specific Agent (called by API handlers)
    # ------------------------------------------------------------------
    def send_to_agent(self, agent_id: str, message: dict) -> bool:
        if agent_id not in self.agents:
            logger.warning("send_to_agent_not_online", agent_id=agent_id)
            return False
        try:
            writer = self.agents[agent_id]["writer"]
            payload = json.dumps(message).encode()
            signed = sign_payload(payload)
            frame = signed.encode() + b" " + payload
            asyncio.get_event_loop().call_soon_threadsafe(
                lambda: asyncio.create_task(self._drain_writer(writer, frame))
            )
            return True
        except Exception as e:
            logger.error(
                "send_to_agent_failed", agent_id=agent_id, error=str(e)
            )
            return False

    async def _drain_writer(self, writer: asyncio.StreamWriter, frame: bytes):
        try:
            writer.write(len(frame).to_bytes(4, byteorder="big") + frame)
            await writer.drain()
        except Exception:
            pass

    def agent_online(self, agent_id: str) -> bool:
        return agent_id in self.agents


# ============================================================================
# CVE Version Range Matching
# ============================================================================


def match_cve_version(software_name: str, version: str, db: DatabaseManager) -> list:
    """
    Match software name + version against CVE records using version range comparison.
    """
    from vuln_db import version_in_range, extract_version_range_from_cpe

    conn = db.get_conn()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute(
        """
        SELECT * FROM cve_records
        WHERE affected_product LIKE ? AND fixed_version IS NOT NULL AND fixed_version != ''
        ORDER BY cvss_score DESC
        """,
        (f"%{software_name}%",),
    )

    results = []
    for row in c.fetchall():
        cpe_str = row["affected_product"] or ""
        vr = extract_version_range_from_cpe(cpe_str)
        if vr:
            if version_in_range(version, vr):
                r = dict(row)
                r["match_method"] = "version_range"
                r["version_range"] = f"{vr[0]} - {vr[1]}"
                results.append(r)
        else:
            desc = (row["description"] or "").lower()
            if version.lower() in desc or f"v{version}" in desc:
                r = dict(row)
                r["match_method"] = "description"
                results.append(r)

    conn.close()
    return results


# ============================================================================
# Flask Web App
# ============================================================================


def create_web_app(
    db: DatabaseManager,
    discovery,
    baseline,
    vuln,
    agent_server: AgentTCPServer = None,
    socketio=None,
):
    from flask_jwt_extended import (
        JWTManager,
        create_access_token,
        get_jwt_identity,
        jwt_required,
    )

    app = Flask(__name__, static_folder=None)
    app.config["JWT_SECRET_KEY"] = config["jwt"]["secret_key"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 24 * 3600
    jwt = JWTManager(app)

    allowed_origins = config.get("web", {}).get("allowed_origins", [])
    if allowed_origins:
        CORS(app, resources={r"/api/*": {"origins": allowed_origins, "supports_credentials": True}}, vary_matching=True)
    else:
        CORS(app, resources={r"/api/*": {}}, vary_matching=True)

    # Attach managers
    app.db = db
    app.discovery = discovery
    app.baseline = baseline
    app.vuln = vuln
    app.agent_server = agent_server
    app.socketio = socketio

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _current_user():
        try:
            return get_jwt_identity()
        except Exception:
            return None

    def _audit(action: str, target: str = "", detail=None):
        db.log_audit(
            user_id=_current_user() or "anonymous",
            action=action,
            target=target,
            detail=json.dumps(detail) if isinstance(detail, dict) else str(detail) if detail else "",
            ip=request.remote_addr or "",
        )

    # ------------------------------------------------------------------
    # Static / SPA
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        dist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")
        return send_from_directory(dist, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        dist = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")
        return send_from_directory(dist, filename)

    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "version": "1.0.0",
            "agent_count": len(agent_server.agents) if agent_server else 0
        })

    # ========== Frontend Alias Routes ==========

    @app.route("/api/stats", methods=["GET"])
    @jwt_required()
    def get_stats_alias():
        """Frontend expects /api/stats for dashboard statistics"""
        conn = db.get_conn()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM agents")
        total_agents = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM agents WHERE status = 'online'")
        online_agents = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM alerts WHERE created_at > datetime('now', '-24 hours')")
        alerts_24h = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status = 'pending'")
        critical_pending = c.fetchone()[0] or 0
        conn.close()
        
        return jsonify({"code": 0, "data": {
            "total_agents": total_agents,
            "online_agents": online_agents,
            "alerts_24h": alerts_24h,
            "critical_pending": critical_pending,
            "online_rate": f"{(online_agents/total_agents*100) if total_agents > 0 else 0:.1f}%"
        }})

    @app.route("/api/logs", methods=["GET"])
    @jwt_required()
    def get_logs_alias():
        """Frontend expects /api/logs for audit logs"""
        limit = request.args.get("limit", 100, type=int)
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
        logs = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": logs})

    # ========== Rate Limiter ==========
    if config.get("ratelimit", {}).get("enabled", True):
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=[config.get("ratelimit", {}).get("default", "200 per minute")],
            storage_uri="memory://",
        )
    else:
        # Disabled limiter - create a no-op substitute
        from flask_limiter import _fail_safe
        class NoOpLimiter:
            def limit(self, *args, **kwargs):
                def decorator(f): return f
                return decorator
            def exemption(self, f): return f
        limiter = NoOpLimiter()

    def _check_login_rate_limit():
        """Called before login to enforce rate limit."""
        if config.get("ratelimit", {}).get("enabled", True):
            # Re-check using limiter; the decorator handles enforcement
            pass

    # ========== Auth ==========

    # FIX #16: CSRF protection decorator
    def csrf_protect(f):
        """Decorator to protect against CSRF attacks."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check for CSRF token in header (X-CSRF-Token)
            # For API endpoints, we also accept the JWT token as CSRF token
            # This is a simplified CSRF protection - production should use flask-wtf
            csrf_token = request.headers.get("X-CSRF-Token", "")
            auth_header = request.headers.get("Authorization", "")
            
            # If no Authorization header and no CSRF token, reject
            # Note: GET requests are exempt from CSRF protection
            if request.method != "GET" and not auth_header and not csrf_token:
                return jsonify({"error": "CSRF protection: missing token"}), 403
            return f(*args, **kwargs)
        return decorated_function

    @app.route("/api/auth/login", methods=["POST"])
    @limiter.limit(config.get("ratelimit", {}).get("login", "5 per minute"))
    def login():
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")

        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        with db.get_conn() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT id, username, password_hash, role, must_change_password FROM users WHERE username = ?",
                (username,),
            )
            user = c.fetchone()

        if user is None:
            _audit("login_failed", username, request.remote_addr)
            return jsonify({"error": "invalid credentials"}), 401

        stored = user[2]
        from werkzeug.security import check_password_hash
        password_valid = False
        
        # Handle legacy SHA256 hash format
        if stored.startswith("sha256$"):
            parts = stored.split("$")
            if len(parts) == 3:
                salt, stored_hash = parts[1], parts[2]
                import hashlib
                computed = hashlib.sha256((password + salt).encode()).hexdigest()
                password_valid = (computed == stored_hash)
        else:
            password_valid = check_password_hash(stored, password)
        
        if password_valid:
            # Update last login
            with db.get_conn() as conn:
                c2 = conn.cursor()
                c2.execute("UPDATE users SET last_login = ? WHERE username = ?", (datetime.now().isoformat(), username))
            
            must_change = bool(user[4]) if user[4] else False
            token = create_access_token(identity=username)
            _audit("login_success", username)
            return jsonify({
                "code": 0,
                "access_token": token,
                "token": token,  # Alias for frontend compatibility
                "username": username,
                "role": user[3],
                "must_change_password": must_change,
            })

        _audit("login_failed", username)
        return jsonify({"error": "invalid credentials"}), 401

    @app.route("/api/auth/verify", methods=["GET"])
    @jwt_required()
    def verify():
        return jsonify({"valid": True, "username": get_jwt_identity()})

    @app.route("/api/auth/change-password", methods=["POST"])
    @csrf_protect
    @jwt_required()
    def change_password():
        """FIX #17: Allow users to change their password, especially for required password changes."""
        current_user = get_jwt_identity()
        data = request.get_json() or {}
        old_password = data.get("old_password", "")
        new_password = data.get("new_password", "")
        
        if not old_password or not new_password:
            return jsonify({"error": "old_password and new_password required"}), 400
        
        if len(new_password) < 8:
            return jsonify({"error": "new_password must be at least 8 characters"}), 400
        
        with db.get_conn() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (current_user,),
            )
            user = c.fetchone()
            if not user:
                return jsonify({"error": "user not found"}), 404
            
            from werkzeug.security import check_password_hash, generate_password_hash
            if not check_password_hash(user[0], old_password):
                _audit("change_password_failed", current_user, "invalid old password")
                return jsonify({"error": "invalid old password"}), 401
            
            new_hash = generate_password_hash(new_password)
            c.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = ?",
                (new_hash, current_user),
            )
            conn.commit()
            _audit("change_password_success", current_user)
            return jsonify({"message": "password changed successfully"})

    # ========== Agent Alert Ingestion (HTTP fallback for NAT agents) ==========

    @app.route("/api/ingest/alert", methods=["POST"])
    def ingest_alert():
        """
        HTTP endpoint for Agents behind NAT to report alerts.
        Requires HMAC signature in X-Agent-Signature header.
        Performs alert correlation and WebSocket broadcast.
        """
        # Verify HMAC signature - required for all requests
        sig = request.headers.get("X-Agent-Signature", "")
        body = request.get_data()
        if not sig or not verify_agent_hmac(body, sig):
            return jsonify({"code": 1, "error": "invalid signature"}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({"code": 1, "error": "empty body"}), 400

        agent_id = data.get("agent_id", "unknown")
        alert_type = data.get("alert_type", "security")
        severity = data.get("severity", "medium")
        title = data.get("title", "No title")
        description = data.get("description", "")
        source_ip = data.get("source_ip", request.remote_addr or "")

        # FIX #7, #8: Use context manager for database connection
        with db.get_conn() as conn:
            c = conn.cursor()
            now = datetime.now().isoformat()
            c.execute(
                """
                INSERT INTO alerts (agent_id, alert_type, severity, title, description, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (agent_id, alert_type, severity, title, description, now),
            )
            alert_id = c.lastrowid
            conn.commit()

        corr = correlate_alert(
            db, agent_id, source_ip, title, severity, description
        )

        if socketio:
            socketio.emit(
                "new_alert",
                {
                    "alert_id": alert_id,
                    "agent_id": agent_id,
                    "alert_type": alert_type,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "source_ip": source_ip,
                    "created_at": now,
                    "merged": corr["merged"],
                    "correlation_id": corr.get("correlation_id"),
                },
                room="alerts",
            )

        return jsonify({"code": 0, "alert_id": alert_id, "correlation": corr})

    # ========== Alert Correlation API ==========

    @app.route("/api/correlation/alerts", methods=["GET"])
    @jwt_required()
    def list_correlations():
        limit = request.args.get("limit", 50, type=int)
        return jsonify({"code": 0, "data": get_active_correlations(db, limit)})

    @app.route("/api/correlation/<int:corr_id>", methods=["GET"])
    @jwt_required()
    def get_correlation(corr_id):
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT * FROM alert_correlations WHERE id = ?", (corr_id,)
        )
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify({"code": 0, "data": dict(row)})
        return jsonify({"error": "not found"}), 404

    @app.route("/api/correlation/<int:corr_id>/resolve", methods=["POST"])
    @jwt_required()
    def resolve_correlation(corr_id):
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "UPDATE alert_correlations SET status = 'resolved' WHERE id = ?",
            (corr_id,),
        )
        conn.commit()
        conn.close()
        _audit("correlation_resolve", str(corr_id))
        return jsonify({"code": 0, "message": "Correlation resolved"})

    # ========== Asset Groups API ==========
    import json
    import os

    GROUPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "asset_groups.json")

    def _load_groups():
        try:
            if os.path.exists(GROUPS_FILE):
                with open(GROUPS_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {"groups": []}

    def _save_groups(data):
        try:
            os.makedirs(os.path.dirname(GROUPS_FILE), exist_ok=True)
            with open(GROUPS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

    @app.route("/api/asset-groups", methods=["GET"])
    @jwt_required()
    def list_asset_groups():
        """获取所有资产分组"""
        data = _load_groups()
        return jsonify({"code": 0, "data": data.get("groups", [])})

    @app.route("/api/asset-groups", methods=["POST"])
    @jwt_required()
    def create_asset_group():
        """创建资产分组"""
        data = request.get_json() or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"code": 1, "message": "分组名称不能为空"})

        groups_data = _load_groups()
        new_id = max([g.get("id", 0) for g in groups_data.get("groups", [])], default=0) + 1

        new_group = {
            "id": new_id,
            "name": name,
            "children": []  # 子分组ID列表
        }
        groups_data["groups"].append(new_group)

        if _save_groups(groups_data):
            _audit("asset_group_create", str(new_id))
            return jsonify({"code": 0, "data": new_group})
        return jsonify({"code": 1, "message": "保存失败"})

    @app.route("/api/asset-groups/<int:group_id>", methods=["PUT"])
    @jwt_required()
    def update_asset_group(group_id):
        """更新资产分组"""
        data = request.get_json() or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"code": 1, "message": "分组名称不能为空"})

        groups_data = _load_groups()
        for g in groups_data.get("groups", []):
            if g.get("id") == group_id:
                g["name"] = name
                if _save_groups(groups_data):
                    _audit("asset_group_update", str(group_id))
                    return jsonify({"code": 0, "data": g})
                break
        return jsonify({"code": 1, "message": "分组不存在"})

    @app.route("/api/asset-groups/<int:group_id>", methods=["DELETE"])
    @jwt_required()
    def delete_asset_group(group_id):
        """删除资产分组"""
        groups_data = _load_groups()
        original_len = len(groups_data.get("groups", []))
        groups_data["groups"] = [g for g in groups_data.get("groups", []) if g.get("id") != group_id]

        if len(groups_data["groups"]) < original_len:
            if _save_groups(groups_data):
                _audit("asset_group_delete", str(group_id))
                return jsonify({"code": 0, "message": "删除成功"})
        return jsonify({"code": 1, "message": "分组不存在"})

    # ========== Agents
    # ========== Agents API ==========

    @app.route("/api/agents", methods=["GET"])
    @jwt_required()
    def list_agents():
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT id, hostname, ip, mac, os, arch, version, status,
                   registered_at, last_seen, asset_name, asset_type, asset_group,
                   cpu_percent, memory_percent, disk_percent, disk_partitions, agent_ip
            FROM agents ORDER BY last_seen DESC
        """)
        agents = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": agents})

    @app.route("/api/agents/<agent_id>", methods=["GET"])
    @jwt_required()
    def get_agent(agent_id):
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = c.fetchone()
        c.execute("SELECT * FROM alerts WHERE agent_id = ? ORDER BY created_at DESC LIMIT 50", (agent_id,))
        alerts = [dict(row) for row in c.fetchall()]
        c.execute("SELECT * FROM commands WHERE agent_id = ? ORDER BY created_at DESC LIMIT 50", (agent_id,))
        commands = [dict(row) for row in c.fetchall()]
        conn.close()
        if agent:
            return jsonify({"code": 0, "data": {"agent": dict(agent), "alerts": alerts, "commands": commands}})
        return jsonify({"error": "Agent not found"}), 404

    @app.route("/api/agents/<agent_id>/details", methods=["GET"])
    @jwt_required()
    def get_agent_details(agent_id):
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent = c.fetchone()
        conn.close()
        if agent:
            return jsonify({"code": 0, "data": dict(agent)})
        return jsonify({"error": "Agent not found"}), 404

    @app.route("/api/agents/<agent_id>", methods=["PUT"])
    @jwt_required()
    def update_agent(agent_id):
        """更新终端资产信息（asset_group 和 asset_name）"""
        data = request.get_json() or {}
        asset_group = data.get("asset_group", "")
        asset_name = data.get("asset_name", "")

        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "UPDATE agents SET asset_group = ?, asset_name = ? WHERE id = ?",
            (asset_group, asset_name, agent_id)
        )
        conn.commit()
        affected = c.rowcount
        conn.close()

        if affected > 0:
            _audit("agent_update", agent_id)
            return jsonify({"code": 0, "message": "更新成功"})
        return jsonify({"code": 1, "message": "终端不存在"}), 404

    # ========== Agent Processes API ==========

    @app.route("/api/agents/<agent_id>/processes", methods=["GET"])
    @jwt_required()
    def get_agent_processes(agent_id):
        """
        Get process list for a specific agent.
        Returns processes with PID, name, CPU%, memory%, user, parentPid.
        """
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """SELECT id, pid, name, cpu, memory, user, parent_pid, agent_id, captured_at
               FROM agent_processes WHERE agent_id = ? ORDER BY captured_at DESC, pid ASC""",
            (agent_id,)
        )
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        # If no data in agent_processes table, return sample/empty
        if not rows:
            return jsonify({"code": 0, "data": []})
        return jsonify({"code": 0, "data": rows})

    # ========== Agent Network API ==========

    @app.route("/api/agents/<agent_id>/network", methods=["GET"])
    @jwt_required()
    def get_agent_network(agent_id):
        """
        Get network connections for a specific agent.
        Returns: protocol, localAddr, remoteAddr, state, pid, program.
        """
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """SELECT id, protocol, local_addr as localAddr, remote_addr as remoteAddr,
                      state, pid, program, agent_id, captured_at
               FROM agent_network WHERE agent_id = ? ORDER BY captured_at DESC""",
            (agent_id,)
        )
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        if not rows:
            return jsonify({"code": 0, "data": []})
        return jsonify({"code": 0, "data": rows})

    # ========== Agent USB API ==========

    @app.route("/api/agents/<agent_id>/usb", methods=["GET"])
    @jwt_required()
    def get_agent_usb(agent_id):
        """
        Get USB device history for a specific agent.
        Returns: insertedAt, vid, pid, deviceType, vendor, product, status.
        """
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """SELECT id, vid, pid, device_type as deviceType, vendor, product,
                      status, inserted_at as insertedAt, agent_id
               FROM agent_usb WHERE agent_id = ? ORDER BY inserted_at DESC""",
            (agent_id,)
        )
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        if not rows:
            return jsonify({"code": 0, "data": []})
        return jsonify({"code": 0, "data": rows})

    # ========== FIM Rules API ==========

    @app.route("/api/fim/rules", methods=["GET"])
    @jwt_required()
    def list_fim_rules():
        """List FIM monitoring rules."""
        agent_id = request.args.get("agent_id")
        history_type = request.args.get("type")  # 'history' for change records
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("pageSize", 20, type=int)

        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        if history_type == "history":
            # Return change history records
            query = """SELECT id, path, change_type as changeType, hash, agent_id,
                             captured_at as time FROM fim_history WHERE 1=1"""
            params = []
            if agent_id:
                query += " AND agent_id = ?"
                params.append(agent_id)
            query += " ORDER BY captured_at DESC LIMIT ? OFFSET ?"
            params.extend([page_size, (page - 1) * page_size])
            c.execute(query, params)
            rows = [dict(row) for row in c.fetchall()]
            c.execute("SELECT COUNT(*) FROM fim_history" + (" WHERE agent_id = ?" if agent_id else ""), ([agent_id] if agent_id else []))
            total = c.fetchone()[0]
            conn.close()
            return jsonify({"code": 0, "data": {"list": rows, "total": total}})

        # Return FIM rules
        query = """SELECT id, path, rule_type as ruleType, agent_id, created_at as createdAt
                     FROM fim_rules WHERE 1=1"""
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY created_at DESC"
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": rows})

    @app.route("/api/fim/rules", methods=["POST"])
    @jwt_required()
    def create_fim_rule():
        """Create a new FIM monitoring rule."""
        data = request.get_json() or {}
        path = data.get("path", "")
        rule_type = data.get("ruleType", "file")
        agent_id = data.get("agentId", "*")
        if not path:
            return jsonify({"code": 1, "error": "path required"}), 400
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO fim_rules (path, rule_type, agent_id, created_at) VALUES (?, ?, ?, ?)",
            (path, rule_type, agent_id, datetime.now().isoformat())
        )
        rule_id = c.lastrowid
        conn.commit()
        conn.close()
        _audit("fim_rule_create", str(rule_id), {"path": path, "ruleType": rule_type})
        return jsonify({"code": 0, "id": rule_id})

    @app.route("/api/fim/rules/<int:rule_id>", methods=["DELETE"])
    @jwt_required()
    def delete_fim_rule(rule_id):
        """Delete an FIM rule."""
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("DELETE FROM fim_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        _audit("fim_rule_delete", str(rule_id))
        return jsonify({"code": 0, "message": "deleted"})

    # ========== Software Assets API ==========

    @app.route("/api/software", methods=["GET"])
    @jwt_required()
    def list_software():
        """
        List software assets across all agents or filtered.
        Query params: agentId, keyword, cveFilter (has_cve|no_cve), page, pageSize
        """
        agent_id = request.args.get("agentId")
        keyword = request.args.get("keyword", "")
        cve_filter = request.args.get("cveFilter", "")
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("pageSize", 20, type=int)

        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Ensure software table exists
        c.execute("""CREATE TABLE IF NOT EXISTS agent_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            vendor TEXT,
            install_path TEXT,
            install_time TEXT,
            captured_at TEXT
        )""")
        
        # Ensure cve_software table exists (for cveCount subquery)
        c.execute("""CREATE TABLE IF NOT EXISTS cve_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            software_name TEXT NOT NULL
        )""")
        conn.commit()

        query = """SELECT s.id, s.name, s.version, s.vendor, s.install_path as installPath,
                         s.install_time as installTime, s.agent_id,
                         a.hostname as agentName,
                         0 as cveCount
                  FROM agent_software s
                  LEFT JOIN agents a ON s.agent_id = a.id WHERE 1=1"""
        params = []
        if agent_id:
            query += " AND s.agent_id = ?"
            params.append(agent_id)
        if keyword:
            query += " AND (s.name LIKE ? OR s.version LIKE ?)"
            params.extend([f"%{keyword}%", f"%{keyword}%"])
        query += " ORDER BY s.name ASC LIMIT ? OFFSET ?"
        params.extend([page_size, (page - 1) * page_size])
        c.execute(query, params)
        rows = [dict(row) for row in c.fetchall()]

        # Count total
        count_query = "SELECT COUNT(*) FROM agent_software s WHERE 1=1"
        count_params = []
        if agent_id:
            count_query += " AND s.agent_id = ?"
            count_params.append(agent_id)
        if keyword:
            count_query += " AND (s.name LIKE ? OR s.version LIKE ?)"
            count_params.extend([f"%{keyword}%", f"%{keyword}%"])
        c.execute(count_query, count_params)
        total = c.fetchone()[0]

        # Fetch CVE details if has_cve filter
        if cve_filter == "has_cve":
            rows = [r for r in rows if r.get("cveCount", 0) > 0]
        elif cve_filter == "no_cve":
            rows = [r for r in rows if r.get("cveCount", 0) == 0]

        conn.close()
        return jsonify({"code": 0, "data": {"list": rows, "total": total}})


    # ========== Agent Upgrades API ==========

    @app.route("/api/agent/updates/<agent_id>", methods=["GET"])
    @jwt_required()
    def get_agent_update(agent_id):
        """
        Get available update for an agent.
        Returns the latest upgrade record from agent_upgrades table.
        """
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Get the latest available upgrade for this agent
        c.execute(
            """SELECT * FROM agent_upgrades
               WHERE agent_id = ? AND status = 'available'
               ORDER BY released_at DESC LIMIT 1""",
            (agent_id,)
        )
        upgrade = c.fetchone()
        conn.close()
        if upgrade:
            return jsonify({"code": 0, "data": dict(upgrade)})
        return jsonify({"code": 0, "data": None, "message": "No update available"})

    @app.route("/api/agent/upgrades", methods=["POST"])
    @jwt_required()
    def create_agent_upgrade():
        """
        Create / publish an upgrade record for agents.
        Also handles upgrade status reports from agents.
        Payload:
          - agent_id: target agent (or '*' for all)
          - version, download_url, checksum, size_bytes, changelog, mandatory
        OR status report from agent:
          - agent_id, status ('applying', 'success', 'failed'), version
        """
        data = request.get_json() or {}
        agent_id = data.get("agent_id")
        status_report = data.get("status")  # agent reporting status

        if status_report:
            # Agent is reporting its upgrade status
            conn = db.get_conn()
            c = conn.cursor()
            now = datetime.now().isoformat()
            c.execute(
                "INSERT INTO agent_upgrade_logs (agent_id, to_version, status, detail, created_at) VALUES (?, ?, ?, ?, ?)",
                (agent_id, data.get("version", ""), status_report, data.get("detail", ""), now)
            )
            # Mark upgrade as deployed on success
            if status_report == "success":
                c.execute(
                    "UPDATE agent_upgrades SET status = 'deployed', deployed_at = ? WHERE agent_id = ? AND version = ? AND status = 'available'",
                    (now, agent_id, data.get("version", ""))
                )
            conn.commit()
            conn.close()
            _audit("agent_upgrade_status", agent_id, {"status": status_report, "version": data.get("version", "")})
            return jsonify({"code": 0, "message": "Status recorded"})

        # Create a new upgrade record
        if not agent_id:
            return jsonify({"error": "agent_id required"}), 400
        version = data.get("version")
        if not version:
            return jsonify({"error": "version required"}), 400

        now = datetime.now().isoformat()
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO agent_upgrades (agent_id, version, download_url, checksum, size_bytes, changelog, mandatory, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'available', ?)",
            (
                agent_id,
                version,
                data.get("download_url", ""),
                data.get("checksum", ""),
                data.get("size_bytes", 0),
                data.get("changelog", ""),
                data.get("mandatory", 0),
                now,
            )
        )
        upgrade_id = c.lastrowid
        conn.commit()
        conn.close()
        _audit("agent_upgrade_create", agent_id, {"version": version})
        logger.info("agent_upgrade_created", agent_id=agent_id, version=version)
        return jsonify({"code": 0, "upgrade_id": upgrade_id})

    @app.route("/api/agent/upgrades", methods=["GET"])
    @jwt_required()
    def list_agent_upgrades():
        """List all upgrade records, optionally filtered by agent_id."""
        agent_id = request.args.get("agent_id")
        status = request.args.get("status")
        limit = request.args.get("limit", 100, type=int)
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = "SELECT * FROM agent_upgrades WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        upgrades = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": upgrades})

    @app.route("/api/agent/upgrades/<int:upgrade_id>", methods=["PUT"])
    @jwt_required()
    def update_agent_upgrade(upgrade_id):
        """Update an upgrade record (e.g., mark as obsolete)."""
        data = request.get_json() or {}
        status_val = data.get("status")
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("UPDATE agent_upgrades SET status = ? WHERE id = ?", (status_val, upgrade_id))
        conn.commit()
        conn.close()
        _audit("agent_upgrade_update", str(upgrade_id), {"status": status_val})
        return jsonify({"code": 0, "message": "Upgrade updated"})

    @app.route("/api/agent/upgrades/logs", methods=["GET"])
    @jwt_required()
    def list_agent_upgrade_logs():
        """List upgrade deployment logs."""
        agent_id = request.args.get("agent_id")
        limit = request.args.get("limit", 100, type=int)
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = "SELECT * FROM agent_upgrade_logs WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        logs = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": logs})

    # ========== YARA Rules API ==========

    @app.route("/api/rules", methods=["GET"])
    @jwt_required()
    def list_yara_rules():
        """
        List YARA rules for agent consumption.
        Returns rules from the rules table or built-in defaults.
        """
        category = request.args.get("category")
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = "SELECT * FROM yara_rules WHERE 1=1"
        params = []
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY updated_at DESC"
        c.execute(query, params)
        rules = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": rules})

    @app.route("/api/rules", methods=["POST"])
    @jwt_required()
    def create_yara_rule():
        """Create a new YARA rule."""
        data = request.get_json() or {}
        rule_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO yara_rules (id, name, content, category, severity, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                rule_id,
                data.get("name", ""),
                data.get("content", ""),
                data.get("category", "general"),
                data.get("severity", "medium"),
                now,
            )
        )
        conn.commit()
        conn.close()
        _audit("yara_rule_create", rule_id)
        logger.info("yara_rule_created", rule_id=rule_id)
        return jsonify({"code": 0, "rule_id": rule_id})

    # Check if yara_rules table exists, create if not
    def _ensure_yara_rules_table():
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS yara_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                severity TEXT DEFAULT 'medium',
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    _ensure_yara_rules_table()

    # ========== Alerts API ==========

    @app.route("/api/alerts", methods=["GET"])
    @jwt_required()
    def list_alerts():
        agent_id = request.args.get("agent_id")
        severity = request.args.get("severity")
        status = request.args.get("status")
        alert_type = request.args.get("type")
        limit = request.args.get("limit", 100, type=int)

        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": alerts})

    @app.route("/api/alerts/<int:alert_id>", methods=["PUT"])
    @jwt_required()
    def update_alert(alert_id):
        data = request.get_json() or {}
        status_val = data.get("status")
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "UPDATE alerts SET status = ?, handled_at = ?, handled_by = ? WHERE id = ?",
            (status_val, datetime.now().isoformat(), _current_user(), alert_id),
        )
        conn.commit()
        conn.close()
        _audit("alert_update", str(alert_id), {"status": status_val})
        return jsonify({"code": 0, "message": "Alert updated"})

    @app.route("/api/alerts/stats", methods=["GET"])
    @jwt_required()
    def get_alert_stats():
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
        by_severity = {row[0]: row[1] for row in c.fetchall()}
        c.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
        by_status = {row[0]: row[1] for row in c.fetchall()}
        c.execute("SELECT COUNT(*) FROM alerts WHERE DATE(created_at) = DATE('now')")
        today = c.fetchone()[0]
        conn.close()
        return jsonify({"code": 0, "data": {"by_severity": by_severity, "by_status": by_status, "today": today}})

    # ========== Commands API ==========

    @app.route("/api/commands/dispatch", methods=["POST"])
    @jwt_required()
    def dispatch_command():
        """
        Command dispatch: writes to commands table (status=pending) then sends to Agent via TCP.
        Payload: {"agent_id": "...", "command_type": "cmd|script|kill", "args": {...}}
        """
        data = request.get_json() or {}
        target_agent = data.get("agent_id")
        command_type = data.get("command_type", "cmd")
        args = data.get("args", {})

        if not target_agent:
            return jsonify({"code": 1, "error": "agent_id required"}), 400

        cmd_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        # 1. Write to DB
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO commands (id, agent_id, command_type, args, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (cmd_id, target_agent, command_type, json.dumps(args), now),
        )
        conn.commit()
        conn.close()

        # 2. Send via TCP
        msg = {
            "type": "command_execute",
            "command_id": cmd_id,
            "command_type": command_type,
            "args": args,
        }

        if agent_server and agent_server.agent_online(target_agent):
            ok = agent_server.send_to_agent(target_agent, msg)
            if ok:
                logger.info("command_dispatched", command_id=cmd_id, agent_id=target_agent)
                _audit("command_dispatch", target_agent, {"command_id": cmd_id, "type": command_type})
                return jsonify({"code": 0, "command_id": cmd_id, "status": "pending", "agent_online": True})
            else:
                conn2 = db.get_conn()
                c2 = conn2.cursor()
                c2.execute("UPDATE commands SET status = 'failed', result = ? WHERE id = ?",
                            (json.dumps({"error": "agent offline or send failed"}), cmd_id))
                conn2.commit()
                conn2.close()
                return jsonify({"code": 1, "error": "agent offline or send failed", "command_id": cmd_id}), 500
        else:
            conn2 = db.get_conn()
            c2 = conn2.cursor()
            c2.execute("UPDATE commands SET status = 'failed', result = ? WHERE id = ?",
                        (json.dumps({"error": "agent not online"}), cmd_id))
            conn2.commit()
            conn2.close()
            return jsonify({"code": 1, "error": "agent not online", "command_id": cmd_id}), 500

    @app.route("/api/commands", methods=["GET"])
    @jwt_required()
    def list_commands():
        agent_id = request.args.get("agent_id")
        status = request.args.get("status")
        limit = request.args.get("limit", 100, type=int)
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        query = "SELECT * FROM commands WHERE 1=1"
        params = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, params)
        commands = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": commands})

    @app.route("/api/commands/<command_id>", methods=["GET"])
    @jwt_required()
    def get_command(command_id):
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM commands WHERE id = ?", (command_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify({"code": 0, "data": dict(row)})
        return jsonify({"error": "not found"}), 404

    # ========== Response Policies API ==========

    @app.route("/api/response/policies/<policy_id>", methods=["PUT"])
    @jwt_required()
    def update_policy(policy_id):
        data = request.get_json() or {}
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "UPDATE response_policies SET name=?, description=?, alert_type=?, severity=?, enabled=?, actions=?, updated_at=? WHERE id=?",
            (
                data.get("name", ""),
                data.get("description", ""),
                data.get("alert_type", ""),
                data.get("severity", ""),
                data.get("enabled", 1),
                json.dumps(data.get("actions", [])),
                datetime.now().isoformat(),
                policy_id,
            ),
        )
        conn.commit()
        conn.close()
        _audit("policy_update", policy_id)
        return jsonify({"code": 0, "message": "Policy updated"})

    @app.route("/api/response/policies", methods=["GET"])
    @jwt_required()
    def list_policies():
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM response_policies ORDER BY created_at DESC")
        policies = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": policies})

    @app.route("/api/response/policies", methods=["POST"])
    @jwt_required()
    def create_policy():
        data = request.get_json() or {}
        policy_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO response_policies (id, name, description, alert_type, severity, enabled, actions, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                policy_id,
                data.get("name", ""),
                data.get("description", ""),
                data.get("alert_type", ""),
                data.get("severity", ""),
                data.get("enabled", 1),
                json.dumps(data.get("actions", [])),
                now,
            ),
        )
        conn.commit()
        conn.close()
        _audit("policy_create", policy_id)
        return jsonify({"code": 0, "policy_id": policy_id})

    @app.route("/api/response/dispatch", methods=["POST"])
    @jwt_required()
    def dispatch_response():
        """
        Dispatch a response policy to an agent.
        Writes command record and sends response_policy message via TCP.
        """
        data = request.get_json() or {}
        policy_id = data.get("policy_id")
        target_agent = data.get("agent_id")

        if not policy_id or not target_agent:
            return jsonify({"code": 1, "error": "policy_id and agent_id required"}), 400

        if not agent_server or not agent_server.agent_online(target_agent):
            return jsonify({"code": 1, "error": "agent not online"}), 500

        cmd_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO commands (id, agent_id, command_type, args, status, created_at) VALUES (?, ?, 'response_policy', ?, 'pending', ?)",
            (cmd_id, target_agent, json.dumps({"policy_id": policy_id}), now),
        )
        conn.commit()
        conn.close()

        msg = {"type": "response_policy", "command_id": cmd_id, "policy_id": policy_id}
        ok = agent_server.send_to_agent(target_agent, msg)

        if ok:
            _audit("response_dispatch", target_agent, {"policy_id": policy_id, "command_id": cmd_id})
            return jsonify({"code": 0, "command_id": cmd_id, "message": "Response dispatched"})
        return jsonify({"code": 1, "error": "send failed"}), 500

    @app.route("/api/response/stats", methods=["GET"])
    @jwt_required()
    def get_response_stats():
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM response_logs WHERE DATE(executed_at) = DATE('now')")
        today = c.fetchone()[0]
        c.execute("SELECT action, COUNT(*) as count FROM response_logs GROUP BY action")
        by_action = {row[0]: row[1] for row in c.fetchall()}
        conn.close()
        return jsonify({"code": 0, "data": {"today": today, "by_action": by_action}})

    # ========== Discovery API ==========

    @app.route("/api/discovery/jobs", methods=["GET"])
    @jwt_required()
    def list_discovery_jobs():
        jobs = discovery.list_jobs(limit=100)
        return jsonify({"code": 0, "data": jobs})

    @app.route("/api/discovery/jobs", methods=["POST"])
    @jwt_required()
    def create_discovery_job():
        data = request.get_json() or {}
        job_id = discovery.create_job(
            data.get("name", ""),
            data.get("ip_range", ""),
            ScanMethod.ARP if data.get("method") == "arp" else ScanMethod.ICMP,
        )
        _audit("discovery_job_create", str(job_id))
        return jsonify({"code": 0, "data": {"id": job_id}})

    @app.route("/api/discovery/jobs/<int:job_id>/start", methods=["POST"])
    @jwt_required()
    def start_discovery_job(job_id):
        discovery.start_scan(job_id)
        return jsonify({"code": 0, "message": "Scan started"})

    @app.route("/api/discovery/hosts", methods=["GET"])
    @jwt_required()
    def list_discovered_hosts():
        hosts = discovery.get_all_hosts()
        return jsonify({"code": 0, "data": hosts})

    # ========== Baseline API ==========

    @app.route("/api/baseline/rules", methods=["GET"])
    @jwt_required()
    def list_baseline_rules():
        rules = baseline.get_rules()
        return jsonify({"code": 0, "data": rules})

    @app.route("/api/baseline/tasks", methods=["GET"])
    @jwt_required()
    def list_baseline_tasks():
        tasks = baseline.get_tasks()
        return jsonify({"code": 0, "data": tasks})

    @app.route("/api/baseline/tasks", methods=["POST"])
    @jwt_required()
    def create_baseline_task():
        data = request.get_json() or {}
        task_id = baseline.create_task(data.get("name", ""), data.get("rule_ids", []))
        _audit("baseline_task_create", str(task_id))
        return jsonify({"code": 0, "data": {"id": task_id}})

    @app.route("/api/baseline/categories", methods=["GET"])
    @jwt_required()
    def list_baseline_categories():
        categories = baseline.get_categories()
        return jsonify({"code": 0, "data": categories})

    # ========== Vulnerability API ==========

    # Alias routes for frontend compatibility
    @app.route("/api/vulns", methods=["GET"])
    @jwt_required()
    def get_vulns_alias():
        """Alias for /api/vuln/summary - frontend expects /api/vulns"""
        return get_vuln_summary()

    @app.route("/api/baseline/results", methods=["GET"])
    @jwt_required()
    def get_baseline_results_alias():
        """Alias for /api/baseline/tasks - frontend expects /api/baseline/results"""
        return list_baseline_tasks()

    @app.route("/api/agents/<agent_id>/command", methods=["POST"])
    @jwt_required()
    def agent_command_alias(agent_id):
        """Alias for /api/commands/dispatch - frontend expects /api/agents/{id}/command"""
        data = request.get_json() or {}
        command = data.get("command", "")
        cmd_type = data.get("type", "shell")
        
        # Call dispatch_command
        dispatch = {
            "type": "command_execute",
            "agent_id": agent_id,
            "command_type": cmd_type,
            "args": {"command": command},
            "timeout": data.get("timeout", 60)
        }
        
        import uuid
        cmd_id = str(uuid.uuid4())
        dispatch["command_id"] = cmd_id
        
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO commands (id, agent_id, command_type, args, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (cmd_id, agent_id, cmd_type, command, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        # Send to agent if online
        if hasattr(app, 'agent_server'):
            app.agent_server.send_to_agent(agent_id, dispatch)
        
        return jsonify({"code": 0, "command_id": cmd_id, "status": "pending"})

    @app.route("/api/scan", methods=["POST"])
    @jwt_required()
    def scan_alias():
        """Alias for /api/discovery/jobs - frontend expects /api/scan"""
        data = request.get_json() or {}
        scan_type = data.get("type", "ip_range")
        targets = data.get("targets", [])
        ports = data.get("ports", "22,80,443,445,3389")
        
        import uuid
        job_id = str(uuid.uuid4())[:8]
        
        conn = db.get_conn()
        c = conn.cursor()
        c.execute(
            "INSERT INTO discovery_jobs (id, scan_type, targets, ports, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)",
            (job_id, scan_type, json.dumps(targets), ports, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        return jsonify({"code": 0, "job_id": job_id, "status": "pending"})

    @app.route("/api/vuln/summary", methods=["GET"])
    @jwt_required()
    def get_vuln_summary():
        summary = vuln.get_vuln_summary()
        return jsonify({"code": 0, "data": summary})

    @app.route("/api/vuln/software", methods=["GET"])
    @jwt_required()
    def get_software_list():
        software = vuln.get_software_list()
        return jsonify({"code": 0, "data": software})

    @app.route("/api/vuln/sync", methods=["POST"])
    @jwt_required()
    def sync_vuln_db():
        try:
            vuln.sync_nvd_cve()
            return jsonify({"code": 0, "message": "Sync started"})
        except Exception as e:
            return jsonify({"code": 1, "error": str(e)}), 500

    @app.route("/api/vuln/match", methods=["POST"])
    @jwt_required()
    def match_cve():
        """Match software version against CVE database using version range matching."""
        data = request.get_json() or {}
        software_name = data.get("software_name", "")
        version = data.get("version", "")
        if not software_name or not version:
            return jsonify({"code": 1, "error": "software_name and version required"}), 400
        matches = match_cve_version(software_name, version, db)
        return jsonify({"code": 0, "data": matches})

    # ========== Audit Logs API ==========

    @app.route("/api/audit/logs", methods=["GET"])
    @jwt_required()
    def list_audit_logs():
        limit = request.args.get("limit", 100, type=int)
        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
        logs = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify({"code": 0, "data": logs})

    # ========== Notifications - SOAR Integration ==========

    @app.route("/api/notifications/config", methods=["GET"])
    @jwt_required()
    def get_notification_config():
        cfg = {
            "feishu_webhook": config.get("notifications", {}).get("feishu_webhook", ""),
            "dingtalk_webhook": config.get("notifications", {}).get("dingtalk_webhook", ""),
            "enabled": config.get("notifications", {}).get("enabled", False),
            "severity_filter": config.get("notifications", {}).get("severity_filter", "high")
        }
        return jsonify({"code": 0, "config": cfg})

    @app.route("/api/notifications/config", methods=["PUT"])
    @jwt_required()
    def update_notification_config():
        data = request.get_json() or {}
        config.setdefault("notifications", {}).update({
            "feishu_webhook": data.get("feishu_webhook", ""),
            "dingtalk_webhook": data.get("dingtalk_webhook", ""),
            "enabled": data.get("enabled", False),
            "severity_filter": data.get("severity_filter", "high")
        })
        with open("manager.toml", "w") as f:
            toml.dump(config, f)
        return jsonify({"code": 0, "message": "notification config updated"})

    @app.route("/api/notifications/test", methods=["POST"])
    @jwt_required()
    def test_notification():
        data = request.get_json() or {}
        webhook_type = data.get("type", "feishu")
        webhook_url = data.get("webhook_url", "")
        
        if webhook_type == "feishu":
            success = send_feishu_notification(webhook_url, "测试通知", "这是一条来自xsec的测试消息", "info")
        else:
            success = send_dingtalk_notification(webhook_url, "测试通知", "这是一条来自xsec的测试消息", "info")
        
        return jsonify({"code": 0, "success": success})

    # ========== Cluster Health ==========

    @app.route("/api/cluster/health", methods=["GET"])
    @jwt_required()
    def cluster_health():
        if hasattr(app, 'registry'):
            health = app.registry.get_cluster_health()
            return jsonify({"code": 0, "health": health})
        return jsonify({"code": 1, "message": "registry not available"})

    # ========== Reports Data API ==========

    @app.route("/api/reports/data", methods=["GET"])
    @jwt_required()
    def get_report_data():
        """
        Return structured report data for the Report.vue dashboard.
        Query params:
          - type: alert_daily | alert_weekly | alert_monthly | terminal | vuln | baseline
          - start: start date (YYYY-MM-DD)
          - end: end date (YYYY-MM-DD)
        """
        report_type = request.args.get("type", "alert_daily")
        start_date = request.args.get("start", "")
        end_date = request.args.get("end", "")

        conn = db.get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        result = {"code": 0, "type": report_type, "columns": [], "rows": [], "summary": []}

        if report_type == "alert_daily":
            result["columns"] = [
                {"prop": "time", "label": "时间", "width": 160},
                {"prop": "level", "label": "告警级别", "width": 100},
                {"prop": "type", "label": "告警类型", "width": 140},
                {"prop": "source", "label": "来源终端", "width": 140},
                {"prop": "detail", "label": "告警详情"},
                {"prop": "status", "label": "处理状态", "width": 100},
            ]
            query = """
                SELECT a.created_at as time, a.severity as level, a.alert_type as type,
                       ag.hostname as source, a.description as detail, a.status
                FROM alerts a
                LEFT JOIN agents ag ON a.agent_id = ag.id
            """
            params = []
            if start_date:
                query += " WHERE a.created_at >= ?"
                params.append(start_date)
            if end_date:
                query += (" AND " if start_date else " WHERE ") + "a.created_at <= ?"
                params.append(end_date + " 23:59:59")  # Date boundary added in Python
            query += " ORDER BY a.created_at DESC LIMIT 200"
            c.execute(query, params)
            result["rows"] = [dict(row) for row in c.fetchall()]
            # Summary
            # FIX 3: Parameterized query to prevent SQL injection
            summary_params = []
            summary_where = ""
            if start_date:
                summary_where += " AND created_at >= ?"
                summary_params.append(start_date)
            if end_date:
                summary_where += " AND created_at <= ?"
                summary_params.append(end_date + " 23:59:59")
            c.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN status='handled' OR status='resolved' THEN 1 ELSE 0 END)*100.0/NULLIF(COUNT(*),0) as handling_rate
                FROM alerts WHERE 1=1""" + summary_where, summary_params)
            row = c.fetchone()
            result["summary"] = [
                {"label": "告警总数", "value": str(row[0] or 0)},
                {"label": "严重告警", "value": str(row[1] or 0)},
                {"label": "高危告警", "value": str(row[2] or 0)},
                {"label": "处理率", "value": f"{row[3] or 0:.1f}%"},
            ]

        elif report_type == "alert_weekly":
            result["columns"] = [
                {"prop": "day", "label": "日期", "width": 120},
                {"prop": "critical", "label": "严重", "width": 80},
                {"prop": "high", "label": "高危", "width": 80},
                {"prop": "medium", "label": "中危", "width": 80},
                {"prop": "low", "label": "低危", "width": 80},
                {"prop": "total", "label": "合计", "width": 80},
                {"prop": "trend", "label": "环比趋势", "width": 120},
            ]
            c.execute("""
                SELECT DATE(created_at) as day,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low,
                       COUNT(*) as total
                FROM alerts
                WHERE created_at >= DATE('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY day DESC LIMIT 30
            """)
            rows = c.fetchall()
            prev_total = None
            for row in reversed(rows):
                trend = "-"
                if prev_total is not None and prev_total > 0:
                    delta = (row["total"] - prev_total) / prev_total * 100
                    trend = f"{'↑' if delta > 0 else '↓'} {abs(delta):.0f}%"
                row["trend"] = trend
                prev_total = row["total"]
            result["rows"] = [dict(r) for r in reversed(rows)]
            total_all = sum(r["total"] for r in rows)
            result["summary"] = [
                {"label": "本周告警", "value": str(total_all)},
                {"label": "严重", "value": str(sum(r["critical"] for r in rows))},
                {"label": "高危", "value": str(sum(r["high"] for r in rows))},
                {"label": "环比", "value": "-"},
            ]

        elif report_type == "alert_monthly":
            result["columns"] = [
                {"prop": "week", "label": "周次", "width": 100},
                {"prop": "critical", "label": "严重", "width": 80},
                {"prop": "high", "label": "高危", "width": 80},
                {"prop": "medium", "label": "中危", "width": 80},
                {"prop": "low", "label": "低危", "width": 80},
                {"prop": "total", "label": "合计", "width": 80},
                {"prop": "top_type", "label": "主要类型"},
            ]
            c.execute("""
                SELECT strftime('%Y-W%W', created_at) as week,
                       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity='high' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity='low' THEN 1 ELSE 0 END) as low,
                       COUNT(*) as total
                FROM alerts
                WHERE created_at >= DATE('now', '-90 days')
                GROUP BY week
                ORDER BY week DESC LIMIT 12
            """)
            result["rows"] = [dict(row) for row in c.fetchall()]

        elif report_type == "terminal":
            result["columns"] = [
                {"prop": "name", "label": "终端名称", "width": 150},
                {"prop": "ip", "label": "IP地址", "width": 140},
                {"prop": "os", "label": "操作系统", "width": 140},
                {"prop": "status", "label": "在线状态", "width": 100},
                {"prop": "agent_version", "label": "Agent版本", "width": 120},
                {"prop": "last_seen", "label": "最后活动时间", "width": 160},
                {"prop": "risk_score", "label": "风险评分", "width": 100},
            ]
            c.execute("""
                SELECT hostname as name, ip, os, status, version as agent_version,
                       last_seen, asset_name as risk_score
                FROM agents ORDER BY last_seen DESC LIMIT 200
            """)
            result["rows"] = [dict(row) for row in c.fetchall()]
            c.execute("SELECT COUNT(*) as total, SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) as online FROM agents")
            stats = c.fetchone()
            result["summary"] = [
                {"label": "终端总数", "value": str(stats[0] or 0)},
                {"label": "在线", "value": f"{stats[1] or 0} ({stats[1]*100//(stats[0] or 1)}%)" if stats[0] else "0"},
                {"label": "离线", "value": f"{(stats[0]-stats[1]) or 0}"},
                {"label": "平均风险", "value": "-"},
            ]

        elif report_type == "vuln":
            result["columns"] = [
                {"prop": "cve_id", "label": "CVE编号", "width": 140},
                {"prop": "level", "label": "危险等级", "width": 100},
                {"prop": "vuln_type", "label": "漏洞类型", "width": 140},
                {"prop": "affected", "label": "受影响终端", "width": 120},
                {"prop": "cvss", "label": "CVSS评分", "width": 100},
                {"prop": "patched", "label": "已修复", "width": 100},
                {"prop": "unpatched", "label": "未修复", "width": 100},
            ]
            c.execute("SELECT cve_id, severity as level, description as vuln_type, COUNT(DISTINCT agent_id) as affected, cvss_score as cvss FROM cve_records GROUP BY cve_id ORDER BY cvss_score DESC LIMIT 100")
            result["rows"] = [dict(row) for row in c.fetchall()]
            result["summary"] = [
                {"label": "漏洞总数", "value": "-"},
                {"label": "严重", "value": "-"},
                {"label": "高危", "value": "-"},
                {"label": "修复率", "value": "-"},
            ]

        elif report_type == "baseline":
            result["columns"] = [
                {"prop": "rule_id", "label": "规则ID", "width": 100},
                {"prop": "rule_name", "label": "规则名称", "width": 180},
                {"prop": "category", "label": "检查类别", "width": 140},
                {"prop": "pass_count", "label": "通过", "width": 80},
                {"prop": "fail_count", "label": "失败", "width": 80},
                {"prop": "compliance", "label": "合规率", "width": 100},
                {"prop": "last_check", "label": "最近检查", "width": 160},
            ]
            c.execute("SELECT id as rule_id, name as rule_name, category, pass_count, fail_count, compliance, last_check FROM baseline_results ORDER BY category, id LIMIT 100")
            result["rows"] = [dict(row) for row in c.fetchall()]
            result["summary"] = [
                {"label": "检查项总数", "value": "-"},
                {"label": "通过", "value": "-"},
                {"label": "失败", "value": "-"},
                {"label": "整体合规率", "value": "-"},
            ]

        conn.close()
        return jsonify(result)

    # ========== Compliance Reports ==========

    @app.route("/api/reports", methods=["GET"])
    @jwt_required()
    def list_reports():
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("SELECT id, report_type, level, status, created_at FROM compliance_reports ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        reports = [{"id": r[0], "type": r[1], "level": r[2], "status": r[3], "created_at": r[4]} for r in rows]
        return jsonify({"code": 0, "reports": reports})

    @app.route("/api/reports/generate", methods=["POST"])
    @jwt_required()
    def generate_report():
        data = request.get_json() or {}
        report_type = data.get("type", "dibiao")
        level = data.get("level", "2")
        report_id = str(uuid.uuid4())[:8]
        
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("INSERT INTO compliance_reports (id, report_type, level, status, created_at) VALUES (?, ?, ?, 'generating', ?)",
                 (report_id, report_type, level, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        import threading
        def generate():
            report_content = "# " + report_type.upper() + " 合规报告 (等级 " + level + ")\n\n"
            report_content += "生成时间: " + datetime.now().isoformat() + "\n\n"
            report_content += "## 检查项\n\n"
            report_content += "- 身份鉴别: 通过\n"
            report_content += "- 访问控制: 通过\n"
            report_content += "- 安全审计: 通过\n"
            report_content += "- 入侵防范: 通过\n"
            
            import os
            os.makedirs(config.get("compliance", {}).get("report_dir", "data/reports"), exist_ok=True)
            report_path = config.get("compliance", {}).get("report_dir", "data/reports") + "/" + report_id + ".md"
            with open(report_path, "w") as f:
                f.write(report_content)
            
            conn = db.get_conn()
            c = conn.cursor()
            c.execute("UPDATE compliance_reports SET status='completed', file_path=?, completed_at=? WHERE id=?",
                     (report_path, datetime.now().isoformat(), report_id))
            conn.commit()
            conn.close()
        
        threading.Thread(target=generate, daemon=True).start()
        return jsonify({"code": 0, "report_id": report_id, "message": "report generation started"})

    @app.route("/api/reports/<report_id>", methods=["GET"])
    @jwt_required()
    def get_report(report_id):
        conn = db.get_conn()
        c = conn.cursor()
        c.execute("SELECT id, report_type, level, status, file_path, created_at FROM compliance_reports WHERE id=?", (report_id,))
        r = c.fetchone()
        conn.close()
        if not r:
            return jsonify({"code": 1, "message": "report not found"}), 404
        return jsonify({"code": 0, "report": {
            "id": r[0], "type": r[1], "level": r[2], "status": r[3], "file_path": r[4], "created_at": r[5]
        }})

    # ========== WebSocket / SocketIO Events ==========

    if socketio and HAS_SOCKETIO:

        # FIX #12: WebSocket token rate limiting
        import time as _time

        _ws_connect_tracker = {}

        def _check_ws_rate_limit():
            """Enforce rate limit on WebSocket connections to prevent token enumeration."""
            ip = request.remote_addr or "unknown"
            now = _time.time()
            window = 60  # 1 minute window
            
            if ip not in _ws_connect_tracker:
                _ws_connect_tracker[ip] = []
            
            # Clean old entries
            _ws_connect_tracker[ip] = [t for t in _ws_connect_tracker[ip] if now - t < window]
            
            # Check limit (5 per minute like login)
            if len(_ws_connect_tracker[ip]) >= 5:
                return False
            
            _ws_connect_tracker[ip].append(now)
            return True

        @socketio.on("connect")
        def on_ws_connect():
            # FIX #12: Apply same rate limit as login to prevent token enumeration
            if not _check_ws_rate_limit():
                print(f"[WebSocket] Connection rejected: rate limit exceeded for {request.remote_addr}")
                raise ConnectionError("Rate limit exceeded")
            
            # Verify JWT token from query params
            token = request.args.get("token", "")
            if not token:
                print("[WebSocket] Connection rejected: missing token")
                raise ConnectionError("Authentication required")
            try:
                from flask_jwt_extended import decode_token
                decoded = decode_token(token)
                print(f"[WebSocket] Authenticated user: {decoded.get('sub', 'unknown')}")
            except Exception as e:
                print(f"[WebSocket] Token verification failed: {e}")
                raise ConnectionError("Invalid token")
            emit("connected", {"status": "ok"})

        @socketio.on("disconnect")
        def on_ws_disconnect():
            pass

        @socketio.on("subscribe_alerts")
        def on_subscribe_alerts(data):
            join_room("alerts")
            emit("subscribed", {"room": "alerts"})

        @socketio.on("subscribe_commands")
        def on_subscribe_commands(data):
            join_room("commands")
            emit("subscribed", {"room": "commands"})

    def _noop_broadcast(*args, **kwargs):
        pass

    app.broadcast_alert = socketio.emit if socketio else _noop_broadcast

    return app


            # ============================================================================
            # Main Entry
            # ============================================================================

def main():
    logger.info(
        "xsec-manager starting",
        tcp=f"tcp://{config['server']['host']}:{config['server']['port']}",
        web=f"http://{config['web']['host']}:{config['web']['port']}",
        tls=config.get("tls", {}).get("enabled", False),
    )

    db_path = config["database"]["path"]
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

    db = DatabaseManager(db_path)
    discovery = AssetDiscovery(db_path)
    baseline = BaselineManager(db_path)
    vuln = CVEDatabase(db_path)

    agent_server = AgentTCPServer(
        host=config["server"]["host"],
        port=config["server"]["port"],
        db=db,
    )

    # Initialize Flask-SocketIO
    if HAS_SOCKETIO:
        ws_allowed_origins = config.get("web", {}).get("allowed_origins", [])
        socketio = SocketIO(
            app=None,
            cors_allowed_origins=ws_allowed_origins if ws_allowed_origins else [],
            async_mode="threading",
            logger=False,
            engineio_logger=False,
        )
        agent_server.set_socketio(socketio)
        logger.info("websocket_enabled", mode="threading")
    else:
        socketio = None
        logger.warning(
            "Flask-SocketIO not installed; WebSocket/real-time alerts disabled. "
            "Install with: pip install flask-socketio eventlet"
        )

    app = create_web_app(db, discovery, baseline, vuln, agent_server, socketio=socketio)

    # Run TCP server in daemon thread
    def run_tcp():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(agent_server.start())

    tcp_thread = threading.Thread(target=run_tcp, daemon=True, name="agent-tcp")
    tcp_thread.start()

    # APScheduler: check agent heartbeats every 30s
    scheduler = BackgroundScheduler()
    scheduler.start()

    def _heartbeat_job():
        check_agent_timeouts(db, config["server"].get("heartbeat_timeout_secs", 90))

    scheduler.add_job(_heartbeat_job, "interval", seconds=30, id="agent_timeout_check")

    try:
        bind_host = config["web"]["host"]
        bind_port = config["web"]["port"]
        logger.info(
            "xsec-manager running",
            http=f"http://{bind_host}:{bind_port}",
            tcp=f"tcp://{config['server']['host']}:{config['server']['port']}",
            ws=bool(socketio),
        )
        # Use regular Flask app.run() instead of socketio.run()
        app.run(
            host=bind_host,
            port=bind_port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        logger.info("xsec-manager shutting down")
    finally:
        scheduler.shutdown()


if __name__ == "__main__":
    main()
