"""
Threat Intelligence RSS Monitoring & Classification System
Production-grade SOC monitoring pipeline for automated threat intelligence ingestion,
classification, enrichment (MITRE ATT&CK), deduplication, multi-sink persistence,
and metric analytics.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import html
import json
import logging
from logging.handlers import RotatingFileHandler
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
import signal
import sqlite3
import sys
import time
from typing import Any
from urllib.parse import urlparse

import colorama
from colorama import Fore, Style
import feedparser
import pandas as pd

# Initialize colorama for cross-platform ANSI support
colorama.init(autoreset=True)


# ==============================================================================
# 1. DATA MODELS & CONFIGURATION
# ==============================================================================

@dataclass(slots=True, frozen=True)
class ThreatAlert:
    """Immutable representation of a normalized, enriched threat intelligence alert."""
    alert_id: str
    title: str
    source: str
    published_date: str
    summary: str
    category: str
    severity: str
    url: str
    mitre_attack: list[str] = field(default_factory=list)
    ingested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert data model to dictionary with serializable fields."""
        data = asdict(self)
        data["mitre_attack"] = "|".join(self.mitre_attack) if self.mitre_attack else "None"
        return data


@dataclass(slots=True)
class FeedSource:
    """Specification for an external threat intelligence RSS/Atom feed."""
    name: str
    url: str
    enabled: bool = True
    timeout_seconds: int = 15


# Default SOC Threat Intel Feed Catalog
DEFAULT_FEEDS: list[FeedSource] = [
    FeedSource(
        name="CISA Alerts",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ),
    FeedSource(
        name="NIST NVD",
        url="https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    ),
    FeedSource(
        name="Microsoft Security Blog",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
    ),
    FeedSource(
        name="Cisco Talos",
        url="https://blog.talosintelligence.com/rss/",
    ),
    FeedSource(
        name="BleepingComputer",
        url="https://www.bleepingcomputer.com/feed/",
    ),
    FeedSource(
        name="The Hacker News",
        url="https://feeds.feedburner.com/TheHackersNews",
    ),
]


# ==============================================================================
# 2. LOGGING CONFIGURATION
# ==============================================================================

def setup_logging(log_file: str = "threat_monitor.log") -> logging.Logger:
    """Configure structured file and stream logging with rotating file handler."""
    logger = logging.getLogger("ThreatMonitor")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on re-initialization
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    # 10 MB rotating file handler, up to 5 backups
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# ==============================================================================
# 3. THREAT CLASSIFICATION ENGINE (RULE-BASED + MITRE ATT&CK MAPPING)
# ==============================================================================

class ThreatClassifier:
    """
    Keyword and regex-driven threat classification engine for SOC ingestion.
    Classifies raw items into standardized threat categories, assigns triage severity,
    and maps observables to MITRE ATT&CK enterprise tactics and techniques.
    """

    CATEGORIES: list[str] = [
        "Ransomware",
        "Malware",
        "Phishing",
        "Vulnerability",
        "Data Breach",
        "APT",
        "Botnet",
        "Cryptomining",
        "DDoS",
        "Other",
    ]

    SEVERITIES: list[str] = [
        "Critical",
        "High",
        "Medium",
        "Low",
    ]

    # Weighted keyword dictionaries for threat categorization
    CATEGORY_KEYWORDS: dict[str, list[str]] = {
        "Ransomware": [
            "ransomware", "encryptor", "double extortion", "lockbit", "blackcat",
            "alphv", "clop", "akira", "play ransomware", "ransom note", "ransom demand",
            "decryptor", "extortion gang", "rhysida", "darkside", "revil", "conti"
        ],
        "Vulnerability": [
            "vulnerability", "cve-", "zero-day", "0-day", "rce", "remote code execution",
            "privilege escalation", "buffer overflow", "sql injection", "sqli", "xss",
            "cross-site scripting", "path traversal", "arbitrary file upload", "patch tuesday",
            "security update", "proof of concept", "poc exploit", "unauthenticated", "advisory"
        ],
        "Phishing": [
            "phishing", "spear-phishing", "credential harvesting", "evilginx", "aitm",
            "adversary-in-the-middle", "smishing", "vishing", "brand impersonation",
            "fake login", "spoofed domain", "typosquatting", "bec", "business email compromise"
        ],
        "APT": [
            "apt", "nation-state", "advanced persistent threat", "cyberespionage", "cozy bear",
            "fancy bear", "lazarus", "kimsuky", "sandworm", "volt typhoon", "salt typhoon",
            "state-sponsored", "espionage campaign", "target tracking", "muddywater", "charming kitten"
        ],
        "Botnet": [
            "botnet", "mirai", "c2 server", "command and control", "iot botnet", "zombie network",
            "c&c", "necurs", "emotet botnet", "qakbot botnet", "botmaster"
        ],
        "DDoS": [
            "ddos", "distributed denial of service", "syn flood", "udp amplification",
            "denial-of-service", "amplification attack", "layer 7 attack", "packet flood"
        ],
        "Cryptomining": [
            "cryptomining", "cryptojacking", "xmrig", "monero miner", "coinminer",
            "unauthorized mining", "crypto drainer", "mining malware"
        ],
        "Data Breach": [
            "data breach", "data leak", "database exposed", "records stolen", "exfiltrated",
            "dark web leak", "compromised accounts", "credential leak", "sensitive data stolen",
            "unauthorized access to database", "data theft"
        ],
        "Malware": [
            "malware", "trojan", "stealer", "infostealer", "backdoor", "rootkit", "spyware",
            "keylogger", "redline", "lumma", "vidar", "agent tesla", "asyncrat", "loader",
            "dropper", "shellcode", "obfuscated payload"
        ],
    }

    # Severity scoring rules
    CRITICAL_INDICATORS: list[str] = [
        "actively exploited", "in the wild", "0-day", "zero-day", "critical rce",
        "unauthenticated rce", "cvss 10", "cvss 9.", "wormable", "emergency patch",
        "cisa kev", "known exploited vulnerability", "national emergency"
    ]

    HIGH_INDICATORS: list[str] = [
        "remote code execution", "privilege escalation", "ransomware attack",
        "mass exploitation", "credential dumping", "bypassing mfa", "high severity",
        "cvss 8.", "cvss 7.", "data exfiltration", "supply chain attack", "domain controller"
    ]

    MEDIUM_INDICATORS: list[str] = [
        "denial of service", "xss", "cross-site", "phishing campaign", "tampering",
        "medium severity", "cvss 6.", "cvss 5.", "cvss 4.", "malicious package"
    ]

    # MITRE ATT&CK Enterprise Techniques Mapping
    MITRE_MAPPING: dict[str, str] = {
        r"\b(phish|phishing|spear.?phishing|lure)\b": "T1566 - Phishing",
        r"\b(ransomware|encryptor|encrypted files)\b": "T1486 - Data Encrypted for Impact",
        r"\b(rce|remote code execution|exploit(ing|ed)?|cve-\d{4}-\d+)\b": "T1190 - Exploit Public-Facing Application",
        r"\b(privilege escalation|elevation of privilege)\b": "T1068 - Exploitation for Privilege Escalation",
        r"\b(credential dumping|mimikatz|lsass|stolen credentials)\b": "T1003 - OS Credential Dumping",
        r"\b(c2|command and control|beacon|c&c)\b": "T1071 - Application Layer Protocol",
        r"\b(ddos|denial of service|syn flood)\b": "T1498 - Network Denial of Service",
        r"\b(cryptomin|cryptojack|xmrig|coinminer)\b": "T1496 - Resource Hijacking",
        r"\b(exfiltration|stolen records|data leak|data theft)\b": "T1041 - Exfiltration Over C2",
        r"\b(supply chain|malicious package|npm|pypi)\b": "T1195 - Supply Chain Compromise",
        r"\b(infostealer|stealer|keylogger|spyware)\b": "T1056 - Input Capture",
        r"\b(persistence|scheduled task|registry run)\b": "T1053 - Scheduled Task/Job",
        r"\b(lateral movement|psexec|wmi|rdp)\b": "T1021 - Remote Services",
    }

    @classmethod
    def sanitize_text(cls, raw_text: str | None) -> str:
        """Strip HTML tags, decode entities, and normalize whitespace."""
        if not raw_text:
            return ""
        # Remove HTML markup
        clean = re.sub(r"<[^>]*>", " ", raw_text)
        # Unescape HTML entities (&amp;, &lt;, etc.)
        clean = html.unescape(clean)
        # Collapse multiple whitespaces
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

    @classmethod
    def classify_category(cls, title: str, summary: str) -> str:
        """Determine primary threat category using frequency-weighted scoring."""
        combined_text = f"{title} {summary}".lower()
        score_board: dict[str, int] = {cat: 0 for cat in cls.CATEGORIES if cat != "Other"}

        for category, keywords in cls.CATEGORY_KEYWORDS.items():
            for kw in keywords:
                # Titles have 3x weight over body summary
                if kw in title.lower():
                    score_board[category] += 3
                if kw in combined_text:
                    score_board[category] += 1

        top_category = max(score_board, key=score_board.get)
        if score_board[top_category] > 0:
            return top_category
        return "Other"

    @classmethod
    def evaluate_severity(cls, title: str, summary: str, category: str) -> str:
        """Assign SOC triage severity level based on contextual indicators."""
        text = f"{title} {summary}".lower()

        for indicator in cls.CRITICAL_INDICATORS:
            if indicator in text:
                return "Critical"

        for indicator in cls.HIGH_INDICATORS:
            if indicator in text:
                return "High"

        # Baseline categoric overrides
        if category in ("Ransomware", "APT"):
            return "High"

        for indicator in cls.MEDIUM_INDICATORS:
            if indicator in text:
                return "Medium"

        if category in ("Phishing", "DDoS", "Malware", "Vulnerability"):
            return "Medium"

        return "Low"

    @classmethod
    def extract_mitre_attack(cls, title: str, summary: str) -> list[str]:
        """Extract correlated MITRE ATT&CK techniques based on observable indicators."""
        combined_text = f"{title} {summary}".lower()
        matched_techniques: set[str] = set()

        for regex_pattern, technique in cls.MITRE_MAPPING.items():
            if re.search(regex_pattern, combined_text, re.IGNORECASE):
                matched_techniques.add(technique)

        return sorted(matched_techniques)


# ==============================================================================
# 4. DATABASE MANAGER (SQLITE3 WITH INDEXED SCHEMA)
# ==============================================================================

class DatabaseManager:
    """Manages transactional persistence, index creation, deduplication, and aggregates."""

    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Return a SQLite connection with row factory enabled."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self) -> None:
        """Initialize tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source TEXT NOT NULL,
                    published_date TEXT,
                    summary TEXT,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    url TEXT NOT NULL,
                    mitre_attack TEXT,
                    ingested_at TEXT NOT NULL
                )
                """
            )
            # Create indexing for efficient query and deduplication operations
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_published ON alerts(published_date);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ingested ON alerts(ingested_at);")
            conn.commit()

    def alert_exists(self, alert_id: str) -> bool:
        """Check if an alert ID is already registered in the persistent store."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM alerts WHERE alert_id = ? LIMIT 1", (alert_id,))
            return cursor.fetchone() is not None

    def insert_alert(self, alert: ThreatAlert) -> bool:
        """
        Insert alert into SQLite database.
        Returns True if newly inserted, False if it was a duplicate.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, title, source, published_date, summary,
                        category, severity, url, mitre_attack, ingested_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.title,
                        alert.source,
                        alert.published_date,
                        alert.summary,
                        alert.category,
                        alert.severity,
                        alert.url,
                        "|".join(alert.mitre_attack) if alert.mitre_attack else "None",
                        alert.ingested_at,
                    ),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Primary key collision indicates duplicate item
                return False

    def get_all_alerts_dataframe(self) -> pd.DataFrame:
        """Read all alerts directly into a pandas DataFrame."""
        with self._get_connection() as conn:
            df = pd.read_sql_query("SELECT * FROM alerts ORDER BY ingested_at DESC", conn)
            return df

    def get_total_count(self) -> int:
        """Retrieve total alert count from database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            count = cursor.fetchone()[0]
            return int(count)


# ==============================================================================
# 5. FEED MANAGER (THREADED INGESTION, RETRIES & INPUT VALIDATION)
# ==============================================================================

class FeedManager:
    """Handles concurrently fetching, parsing, validating, and extracting RSS/Atom feeds."""

    def __init__(
        self,
        feeds: list[FeedSource],
        logger: logging.Logger,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ):
        self.feeds = [f for f in feeds if f.enabled]
        self.logger = logger
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    @staticmethod
    def generate_alert_id(feed_name: str, entry: dict[str, Any]) -> str:
        """
        Generate deterministic unique identifier for deduplication.
        Prefers entry ID or GUID; falls back to SHA-256 of feed + title + link.
        """
        raw_guid = entry.get("id") or entry.get("guid") or entry.get("link")
        if raw_guid and isinstance(raw_guid, str) and len(raw_guid.strip()) > 5:
            seed = f"{feed_name}::{raw_guid.strip()}"
        else:
            title = entry.get("title", "")
            link = entry.get("link", "")
            seed = f"{feed_name}::{title}::{link}"

        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_url(url: str | None) -> bool:
        """Verify URL conforms to valid HTTP/HTTPS scheme and network location."""
        if not url:
            return False
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False

    @staticmethod
    def normalize_timestamp(entry: dict[str, Any]) -> str:
        """Extract and normalize publication timestamp into ISO 8601 UTC string."""
        if "published_parsed" in entry and entry.published_parsed:
            try:
                struct_time = entry.published_parsed
                dt = datetime(*struct_time[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                pass

        if "updated_parsed" in entry and entry.updated_parsed:
            try:
                struct_time = entry.updated_parsed
                dt = datetime(*struct_time[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except Exception:
                pass

        # Fallback to current UTC time if unavailable
        return datetime.now(timezone.utc).isoformat()

    def fetch_feed_with_retry(self, feed: FeedSource) -> list[dict[str, Any]]:
        """Fetch feed entries with exponential backoff retry mechanism."""
        attempt = 0
        current_delay = 1.5

        while attempt < self.max_retries:
            attempt += 1
            try:
                self.logger.info(
                    "Connecting to feed '%s' (Attempt %d/%d): %s",
                    feed.name,
                    attempt,
                    self.max_retries,
                    feed.url,
                )

                # feedparser handles network fetch with timeout support
                parsed = feedparser.parse(
                    feed.url,
                    request_headers={"User-Agent": "SecOps-ThreatTracker-RSS/2.0"},
                )

                # Check for HTTP status codes indicating failure
                if hasattr(parsed, "status") and parsed.status >= 400:
                    raise ConnectionError(f"HTTP Error {parsed.status} from {feed.url}")

                if parsed.bozo and not parsed.entries:
                    raise ValueError(f"Malformed XML/RSS feed: {parsed.bozo_exception}")

                entries = parsed.entries
                self.logger.info("Successfully fetched %d entries from '%s'", len(entries), feed.name)
                return entries

            except Exception as exc:
                self.logger.warning(
                    "Error parsing feed '%s' on attempt %d: %s",
                    feed.name,
                    attempt,
                    str(exc),
                )
                if attempt < self.max_retries:
                    time.sleep(current_delay)
                    current_delay *= self.backoff_factor

        self.logger.error("All %d retries exhausted for feed '%s'.", self.max_retries, feed.name)
        return []

    def fetch_all_feeds_concurrently(self) -> list[tuple[FeedSource, list[dict[str, Any]]]]:
        """Concurrently fetch entries from all configured feeds via ThreadPoolExecutor."""
        results: list[tuple[FeedSource, list[dict[str, Any]]]] = []
        max_workers = min(len(self.feeds), 8) or 1

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="FeedWorker"
        ) as executor:
            future_to_feed = {
                executor.submit(self.fetch_feed_with_retry, feed): feed
                for feed in self.feeds
            }

            for future in concurrent.futures.as_completed(future_to_feed):
                feed = future_to_feed[future]
                try:
                    entries = future.result()
                    results.append((feed, entries))
                except Exception as exc:
                    self.logger.error("Unhandled exception for feed '%s': %s", feed.name, str(exc))
                    results.append((feed, []))

        return results


# ==============================================================================
# 6. STATISTICS MANAGER (PANDAS & AGGREGATE DASHBOARD STRUCTURES)
# ==============================================================================

class StatisticsManager:
    """Calculates operational SOC metrics using pandas and prepares dashboard-ready structures."""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def compute_all_statistics(self) -> dict[str, Any]:
        """
        Compute comprehensive intelligence statistics:
        - Alerts per category
        - Alerts per source
        - Alerts per severity
        - Daily alert count
        - Dashboard-ready payload
        """
        df = self.db_manager.get_all_alerts_dataframe()

        if df.empty:
            return {
                "total_alerts": 0,
                "alerts_per_category": {},
                "alerts_per_source": {},
                "alerts_per_severity": {},
                "daily_alert_count": {},
                "dashboard_payload": {
                    "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
                    "category_breakdown": [],
                    "source_breakdown": [],
                    "recent_critical": [],
                },
            }

        # 1. Alerts per category
        category_counts = df["category"].value_counts().to_dict()

        # 2. Alerts per source
        source_counts = df["source"].value_counts().to_dict()

        # 3. Alerts per severity
        severity_counts = df["severity"].value_counts().to_dict()

        # 4. Daily alert count (using publication date or ingestion timestamp)
        # Standardize date portion for daily grouping
        try:
            df["day"] = pd.to_datetime(df["ingested_at"], errors="coerce").dt.strftime("%Y-%m-%d")
            daily_counts = df["day"].value_counts().sort_index(ascending=False).to_dict()
        except Exception:
            daily_counts = {}

        # 5. Dashboard-Ready Structure (JSON serializable)
        recent_critical = (
            df[df["severity"].isin(["Critical", "High"])]
            .head(10)[["alert_id", "title", "source", "category", "severity", "url", "ingested_at"]]
            .to_dict(orient="records")
        )

        dashboard_payload = {
            "summary": {
                "total": int(len(df)),
                "critical": int(severity_counts.get("Critical", 0)),
                "high": int(severity_counts.get("High", 0)),
                "medium": int(severity_counts.get("Medium", 0)),
                "low": int(severity_counts.get("Low", 0)),
            },
            "category_breakdown": [
                {"category": cat, "count": int(cnt)} for cat, cnt in category_counts.items()
            ],
            "source_breakdown": [
                {"source": src, "count": int(cnt)} for src, cnt in source_counts.items()
            ],
            "daily_trend": [
                {"date": day, "count": int(cnt)} for day, cnt in daily_counts.items()
            ],
            "recent_critical": recent_critical,
        }

        return {
            "total_alerts": len(df),
            "alerts_per_category": category_counts,
            "alerts_per_source": source_counts,
            "alerts_per_severity": severity_counts,
            "daily_alert_count": daily_counts,
            "dashboard_payload": dashboard_payload,
        }

    def render_statistics_table(self) -> None:
        """Render formatted statistics summary tables directly to terminal."""
        stats = self.compute_all_statistics()
        total = stats["total_alerts"]

        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{Style.BRIGHT}                 SOC THREAT INTELLIGENCE SUMMARY STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"Total Ingested Alerts: {Style.BRIGHT}{total}{Style.RESET_ALL}\n")

        # Severity Table
        print(f"{Fore.WHITE}{Style.BRIGHT}[+] Severity Distribution:{Style.RESET_ALL}")
        for sev in ["Critical", "High", "Medium", "Low"]:
            cnt = stats["alerts_per_severity"].get(sev, 0)
            pct = (cnt / total * 100) if total > 0 else 0.0
            color = (
                Fore.RED
                if sev == "Critical"
                else Fore.LIGHTRED_EX
                if sev == "High"
                else Fore.YELLOW
                if sev == "Medium"
                else Fore.GREEN
            )
            print(f"  {color}• {sev:<10}: {cnt:>5} ({pct:>5.1f}%){Style.RESET_ALL}")

        # Category Table
        print(f"\n{Fore.WHITE}{Style.BRIGHT}[+] Threat Category Breakdown:{Style.RESET_ALL}")
        for cat, cnt in sorted(stats["alerts_per_category"].items(), key=lambda x: x[1], reverse=True):
            pct = (cnt / total * 100) if total > 0 else 0.0
            print(f"  {Fore.MAGENTA}• {cat:<15}: {cnt:>5} ({pct:>5.1f}%){Style.RESET_ALL}")

        # Source Table
        print(f"\n{Fore.WHITE}{Style.BRIGHT}[+] Ingestion By Feed Source:{Style.RESET_ALL}")
        for src, cnt in sorted(stats["alerts_per_source"].items(), key=lambda x: x[1], reverse=True):
            pct = (cnt / total * 100) if total > 0 else 0.0
            print(f"  {Fore.CYAN}• {src:<25}: {cnt:>5} ({pct:>5.1f}%){Style.RESET_ALL}")

        # Daily Distribution
        print(f"\n{Fore.WHITE}{Style.BRIGHT}[+] Daily Alert Velocity (Recent Days):{Style.RESET_ALL}")
        for day, cnt in list(stats["daily_alert_count"].items())[:5]:
            print(f"  {Fore.YELLOW}• {day:<12}: {cnt:>5} alerts{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{'='*80}\n{Style.RESET_ALL}")


# ==============================================================================
# 7. ALERT MANAGER (ORCHESTRATION, FORMATTING & MULTI-SINK PERSISTENCE)
# ==============================================================================

class AlertManager:
    """
    Orchestrates alert lifecycle: validation, classification, SOC console formatting,
    and multi-sink output persistence (CSV, JSON, SQLite).
    """

    def __init__(
        self,
        db_manager: DatabaseManager,
        logger: logging.Logger,
        csv_path: str = "alerts.csv",
        json_path: str = "alerts.json",
    ):
        self.db = db_manager
        self.logger = logger
        self.csv_path = csv_path
        self.json_path = json_path
        self._init_csv_sink()

    def _init_csv_sink(self) -> None:
        """Initialize CSV export file with header if not present."""
        path = Path(self.csv_path)
        if not path.exists() or path.stat().st_size == 0:
            with open(self.csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "alert_id",
                    "title",
                    "source",
                    "published_date",
                    "category",
                    "severity",
                    "url",
                    "mitre_attack",
                    "summary",
                    "ingested_at",
                ])

    def print_soc_alert(self, alert: ThreatAlert) -> None:
        """
        Output high-visibility, SOC-styled colored terminal alert format:
        [TIMESTAMP]
        Source:
        Category:
        Severity:
        Headline:
        Link:
        """
        # Assign color coding based on severity level
        sev_color = {
            "Critical": Fore.RED + Style.BRIGHT,
            "High": Fore.LIGHTRED_EX + Style.BRIGHT,
            "Medium": Fore.YELLOW + Style.BRIGHT,
            "Low": Fore.GREEN,
        }.get(alert.severity, Fore.WHITE)

        border = f"{sev_color}--------------------------------------------------------------------------------{Style.RESET_ALL}"

        print(border)
        print(f"{Fore.WHITE}[{alert.published_date}]{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Source:   {Style.RESET_ALL}{alert.source}")
        print(f"{Fore.MAGENTA}Category: {Style.RESET_ALL}{alert.category}")
        print(f"Severity: {sev_color}{alert.severity}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{Style.BRIGHT}Headline: {Style.RESET_ALL}{alert.title}")
        print(f"{Fore.BLUE}Link:     {Style.RESET_ALL}{alert.url}")

        if alert.mitre_attack:
            mitre_str = ", ".join(alert.mitre_attack)
            print(f"{Fore.YELLOW}MITRE:    {Style.RESET_ALL}{mitre_str}")

        print(border)

    def append_to_csv(self, alert: ThreatAlert) -> None:
        """Append an individual alert row to CSV file sink."""
        with open(self.csv_path, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                alert.alert_id,
                alert.title,
                alert.source,
                alert.published_date,
                alert.category,
                alert.severity,
                alert.url,
                "|".join(alert.mitre_attack) if alert.mitre_attack else "None",
                alert.summary,
                alert.ingested_at,
            ])

    def sync_to_json(self) -> None:
        """Regenerate complete JSON export sink from database."""
        df = self.db.get_all_alerts_dataframe()
        records = df.to_dict(orient="records")
        with open(self.json_path, mode="w", encoding="utf-8") as f:
            json.dump(records, f, indent=2, ensure_ascii=False)

    def process_entry(self, feed: FeedSource, raw_entry: dict[str, Any]) -> ThreatAlert | None:
        """
        Process, validate, classify, deduplicate, and persist a raw RSS entry.
        Returns the created ThreatAlert if novel, or None if skipped or duplicate.
        """
        # 1. Deduplication ID generation
        alert_id = FeedManager.generate_alert_id(feed.name, raw_entry)
        if self.db.alert_exists(alert_id):
            return None

        # 2. Extract and sanitize fields
        title = ThreatClassifier.sanitize_text(raw_entry.get("title", "Untitled Advisory"))
        link = raw_entry.get("link", "").strip()
        if not FeedManager.validate_url(link):
            link = feed.url  # fallback to feed URL if entry link invalid

        # Extract summary or content
        raw_summary = raw_entry.get("summary") or raw_entry.get("description", "")
        if not raw_summary and "content" in raw_entry:
            try:
                raw_summary = raw_entry["content"][0].get("value", "")
            except Exception:
                raw_summary = ""

        summary = ThreatClassifier.sanitize_text(raw_summary)
        published_date = FeedManager.normalize_timestamp(raw_entry)

        # 3. Classify threat category and severity
        category = ThreatClassifier.classify_category(title, summary)
        severity = ThreatClassifier.evaluate_severity(title, summary, category)
        mitre_attack = ThreatClassifier.extract_mitre_attack(title, summary)

        # 4. Construct immutable ThreatAlert
        alert = ThreatAlert(
            alert_id=alert_id,
            title=title,
            source=feed.name,
            published_date=published_date,
            summary=summary,
            category=category,
            severity=severity,
            url=link,
            mitre_attack=mitre_attack,
        )

        # 5. Persist to SQLite
        inserted = self.db.insert_alert(alert)
        if not inserted:
            return None

        # 6. Persist to CSV
        try:
            self.append_to_csv(alert)
        except Exception as exc:
            self.logger.error("Failed to append alert %s to CSV: %s", alert.alert_id, str(exc))

        # 7. Emit SOC terminal notification
        self.print_soc_alert(alert)
        self.logger.info(
            "New Threat Detected: [%s] [%s] %s (Source: %s)",
            alert.severity,
            alert.category,
            alert.title,
            alert.source,
        )

        return alert


# ==============================================================================
# 8. MAIN ORCHESTRATOR & APPLICATION LOOP
# ==============================================================================

class ThreatIntelligenceOrchestrator:
    """Production coordinator managing feed polling cycles, intervals, and graceful shutdowns."""

    def __init__(
        self,
        poll_interval_seconds: int = 300,
        db_path: str = "threat_intel.db",
        csv_path: str = "alerts.csv",
        json_path: str = "alerts.json",
        log_path: str = "threat_monitor.log",
        feeds: list[FeedSource] | None = None,
    ):
        self.poll_interval = poll_interval_seconds
        self.logger = setup_logging(log_path)
        self.db_manager = DatabaseManager(db_path)
        self.alert_manager = AlertManager(self.db_manager, self.logger, csv_path, json_path)
        self.statistics_manager = StatisticsManager(self.db_manager)
        self.feed_manager = FeedManager(feeds or DEFAULT_FEEDS, self.logger)
        self.is_running = True

        # Register OS signal handlers for graceful exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, _frame: Any) -> None:
        """Handle interrupt and termination signals gracefully."""
        sig_name = signal.Signals(signum).name
        print(f"\n{Fore.YELLOW}[!] Received signal {sig_name}. Initiating graceful shutdown...{Style.RESET_ALL}")
        self.logger.info("Termination signal %s received. Halting monitor loop.", sig_name)
        self.is_running = False

    def run_polling_cycle(self) -> int:
        """
        Execute a single end-to-end intelligence collection cycle across all feeds.
        Returns the count of newly ingested alerts in this cycle.
        """
        self.logger.info("Starting feed collection cycle...")
        print(f"\n{Fore.CYAN}[*] Starting Intelligence Collection Sweep: {datetime.now(timezone.utc).isoformat()}{Style.RESET_ALL}")

        feed_results = self.feed_manager.fetch_all_feeds_concurrently()
        new_alerts_count = 0

        for feed, entries in feed_results:
            self.logger.info("Ingesting %d raw items from %s", len(entries), feed.name)
            for entry in entries:
                alert = self.alert_manager.process_entry(feed, entry)
                if alert:
                    new_alerts_count += 1

        # Synchronize JSON sink
        try:
            self.alert_manager.sync_to_json()
        except Exception as exc:
            self.logger.error("Failed synchronizing JSON sink: %s", str(exc))

        print(
            f"{Fore.GREEN}[✓] Collection cycle complete. New unique alerts: {new_alerts_count} | "
            f"Total alerts in store: {self.db_manager.get_total_count()}{Style.RESET_ALL}"
        )
        self.logger.info(
            "Cycle finished. Added %d alerts. Total in repository: %d",
            new_alerts_count,
            self.db_manager.get_total_count(),
        )

        # Output refreshed analytics table
        self.statistics_manager.render_statistics_table()
        return new_alerts_count

    def start(self, run_once: bool = False) -> None:
        """Start the continuous monitoring service loop."""
        banner = rf"""{Fore.RED}{Style.BRIGHT}
  _______ _                    _   _______             _             
 |__   __| |                  | | |__   __|           | |            
    | |  | |__  _ __ ___  __ _| |_   | |_ __ __ _  ___| | _____ _ __ 
    | |  | '_ \| '__/ _ \/ _` | __|  | | '__/ _` |/ __| |/ / _ \ '__|
    | |  | | | | | |  __/ (_| | |_   | | | | (_| | (__|   <  __/ |   
    |_|  |_| |_|_|  \___|\__,_|\__|  |_|_|  \__,_|\___|_|\_\___|_|   
                     [PRODUCTION SOC FEED MONITOR]
{Style.RESET_ALL}
  • Polling Interval: {self.poll_interval} seconds ({self.poll_interval / 60:.1f} min)
  • Storage Sinks:    SQLite (threat_intel.db), CSV (alerts.csv), JSON (alerts.json)
  • Log Output:       threat_monitor.log
  • Monitoring:       {len(self.feed_manager.feeds)} Threat Intelligence Feeds
        """
        print(banner)
        self.logger.info("ThreatTracker service started. Polling interval: %ds", self.poll_interval)

        while self.is_running:
            try:
                self.run_polling_cycle()

                if run_once:
                    print(f"{Fore.YELLOW}[*] Single execution mode requested. Exiting.{Style.RESET_ALL}")
                    break

                # Sleep in short increments to allow rapid response to SIGINT/Ctrl+C
                sleep_counter = 0
                while self.is_running and sleep_counter < self.poll_interval:
                    time.sleep(1)
                    sleep_counter += 1

            except Exception as exc:
                self.logger.critical("Unexpected error in monitor loop: %s", str(exc), exc_info=True)
                print(f"{Fore.RED}[!] Critical runtime exception: {exc}{Style.RESET_ALL}")
                time.sleep(5)

        self.logger.info("ThreatTracker service successfully stopped.")
        print(f"{Fore.GREEN}[*] ThreatTracker shutdown complete. Stay safe!{Style.RESET_ALL}")


# ==============================================================================
# 9. CLI ENTRY POINT
# ==============================================================================

def parse_arguments() -> argparse.Namespace:
    """Configure and parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="SOC Threat Intelligence RSS Monitoring and Classification Engine.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Polling interval in seconds between RSS feed checks (default: 300 / 5 mins)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="threat_intel.db",
        help="Path to SQLite database file",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default="alerts.csv",
        help="Path to CSV export file",
    )
    parser.add_argument(
        "--json",
        type=str,
        default="alerts.json",
        help="Path to JSON export file",
    )
    parser.add_argument(
        "--log",
        type=str,
        default="threat_monitor.log",
        help="Path to rotating log file",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one complete polling sweep and exit immediately",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Display current statistics from existing database and exit",
    )
    return parser.parse_args()


def main() -> None:
    """Program entry point."""
    args = parse_arguments()

    if args.stats:
        db = DatabaseManager(args.db)
        stats = StatisticsManager(db)
        stats.render_statistics_table()
        sys.exit(0)

    orchestrator = ThreatIntelligenceOrchestrator(
        poll_interval_seconds=args.interval,
        db_path=args.db,
        csv_path=args.csv,
        json_path=args.json,
        log_path=args.log,
    )
    orchestrator.start(run_once=args.once)


if __name__ == "__main__":
    main()
