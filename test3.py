#!/usr/bin/env python3
"""Authorized-use JS secret scanner for recon.sh output.

Normal runs print only [FOUND ...] lines. Use --verbose/-v for diagnostics.
The default --max-urls 0 scans every supplied and discovered URL.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import csv
import hashlib
import json
import math
import os
import re
import sys
import threading
import time
import zlib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

USER_AGENT = "Mozilla/5.0 (compatible; ai-secret-scanner/3.2; authorized-assessment)"
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_THREADS = 8
DEFAULT_MAX_URLS = 0
DEFAULT_MAX_DEPTH = 3
DEFAULT_MIN_ENTROPY = 0.58
MAX_RETRIES = 2

RETRY_STATUS = {429, 500, 502, 503, 504}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

CONFIDENCE_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

PRINT_LOCK = threading.Lock()
VERBOSE = False


def log(
    message: str,
    *,
    stdout: bool = False,
    always: bool = False,
) -> None:
    if not always and not VERBOSE:
        return

    with PRINT_LOCK:
        print(
            message,
            file=sys.stdout if stdout else sys.stderr,
            flush=True,
        )


@dataclass(frozen=True)
class Rule:
    provider: str
    category: str
    regex: re.Pattern
    confidence: str
    keywords: Optional[re.Pattern] = None
    secret_group: int = 0


def keywords(*values: str) -> re.Pattern:
    return re.compile(
        r"(?i)(?:%s)"
        % "|".join(re.escape(value) for value in values)
    )


STRICT_RULES: List[Rule] = [
    Rule(
        "openai",
        "llm",
        re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}\b"),
        "high",
    ),
    Rule(
        "openrouter",
        "llm",
        re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{40,}\b"),
        "high",
    ),
    Rule(
        "anthropic",
        "llm",
        re.compile(r"\bsk-ant-(?:api\d+|admin\d+)-[A-Za-z0-9_-]{60,}\b"),
        "high",
    ),
    Rule(
        "perplexity",
        "llm",
        re.compile(r"\bpplx-[A-Za-z0-9_-]{32,}\b"),
        "high",
    ),
    Rule(
        "huggingface",
        "llm",
        re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        "high",
    ),
    Rule(
        "groq",
        "llm",
        re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"),
        "high",
    ),
    Rule(
        "replicate",
        "llm",
        re.compile(r"\br8_[A-Za-z0-9]{32,}\b"),
        "high",
    ),
    Rule(
        "databricks",
        "data",
        re.compile(r"\bdapi[a-f0-9]{32,}\b", re.I),
        "high",
    ),
    Rule(
        "pinecone",
        "vector",
        re.compile(r"\bpcsk_[A-Za-z0-9_-]{30,}\b"),
        "high",
    ),
    Rule(
        "google_api",
        "client_config",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "medium",
    ),
    Rule(
        "google_oauth",
        "cloud",
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
        "high",
    ),
    Rule(
        "aws_access_key",
        "cloud",
        re.compile(
            r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"
        ),
        "high",
    ),
    Rule(
        "github",
        "vcs",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "high",
    ),
    Rule(
        "github_fine_grained",
        "vcs",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        "high",
    ),
    Rule(
        "gitlab",
        "vcs",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "slack",
        "chat",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "high",
    ),
    Rule(
        "stripe_restricted",
        "payments",
        re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        "high",
    ),
    Rule(
        "stripe_or_clerk_secret",
        "auth_payments",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        "high",
    ),
    Rule(
        "sendgrid",
        "email",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        "high",
    ),
    Rule(
        "npm",
        "registry",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "high",
    ),
    Rule(
        "mapbox_secret",
        "maps",
        re.compile(
            r"\b(?:sk|tk)\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\b"
        ),
        "high",
    ),
    Rule(
        "mapbox_public",
        "client_config",
        re.compile(
            r"\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\b"
        ),
        "medium",
    ),
    Rule(
        "posthog_secret",
        "analytics",
        re.compile(r"\bph[xs]_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "posthog_project",
        "client_config",
        re.compile(r"\bphc_[A-Za-z0-9_-]{20,}\b"),
        "medium",
    ),
    Rule(
        "contentful_pat",
        "cms",
        re.compile(r"\bCFPAT-[A-Za-z0-9_-]{40,}\b"),
        "high",
    ),
    Rule(
        "notion",
        "productivity",
        re.compile(r"\bntn_[0-9]{11}[A-Za-z0-9]{35}\b"),
        "high",
    ),
    Rule(
        "linear",
        "productivity",
        re.compile(r"\blin_api_[A-Za-z0-9]{40}\b", re.I),
        "high",
    ),
    Rule(
        "planetscale",
        "data",
        re.compile(
            r"\bpscale_(?:tkn|oauth|pw)_[A-Za-z0-9=._-]{32,}\b",
            re.I,
        ),
        "high",
    ),
    Rule(
        "doppler",
        "secrets",
        re.compile(r"\bdp\.pt\.[A-Za-z0-9]{43}\b", re.I),
        "high",
    ),
    Rule(
        "figma",
        "design",
        re.compile(r"\bfigd_[A-Za-z0-9_-]{40,}\b"),
        "high",
    ),
    Rule(
        "new_relic_user",
        "monitoring",
        re.compile(r"\bNRAK-[a-z0-9]{27}\b", re.I),
        "high",
    ),
    Rule(
        "new_relic_browser",
        "client_config",
        re.compile(r"\bNRJS-[a-f0-9]{19}\b", re.I),
        "medium",
    ),
    Rule(
        "new_relic_insert",
        "monitoring",
        re.compile(r"\bNRII-[A-Za-z0-9-]{32}\b", re.I),
        "high",
    ),
    Rule(
        "cloudflare_origin_ca",
        "cloud",
        re.compile(r"\bv1\.0-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{146}\b"),
        "high",
    ),
    Rule(
        "digitalocean",
        "cloud",
        re.compile(r"\bdop_v1_[A-Fa-f0-9]{64}\b"),
        "high",
    ),
    Rule(
        "shopify",
        "commerce",
        re.compile(r"\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}\b"),
        "high",
    ),
    Rule(
        "grafana",
        "monitoring",
        re.compile(r"\bgl(?:c|sa)_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "sentry",
        "monitoring",
        re.compile(r"\bsntrys_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "dockerhub",
        "registry",
        re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "pypi",
        "registry",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"),
        "high",
    ),
    Rule(
        "sonar",
        "code_quality",
        re.compile(r"\bsqu_[A-Za-z0-9]{40}\b"),
        "high",
    ),
    Rule(
        "resend",
        "email",
        re.compile(r"\bre_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "clerk_publishable",
        "client_config",
        re.compile(r"\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        "medium",
        keywords(
            "clerk",
            "clerk_publishable",
            "publishablekey",
        ),
    ),
    Rule(
        "vercel",
        "cloud",
        re.compile(r"\b(?:vcp|vca)_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "airtable",
        "data",
        re.compile(r"\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b"),
        "high",
    ),
    Rule(
        "square",
        "payments",
        re.compile(r"\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}\b"),
        "high",
    ),
    Rule(
        "mailgun",
        "email",
        re.compile(r"\bkey-[A-Fa-f0-9]{32}\b"),
        "high",
    ),
    Rule(
        "1password_secret_key",
        "secrets",
        re.compile(
            r"\bA3-[A-Z0-9]{6}-"
            r"(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-"
            r"[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"
        ),
        "high",
    ),
    Rule(
        "1password_service_account",
        "secrets",
        re.compile(r"\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}"),
        "high",
    ),
    Rule(
        "age_secret_key",
        "crypto",
        re.compile(
            r"\bAGE-SECRET-KEY-1"
            r"[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"
        ),
        "high",
    ),
    Rule(
        "adobe_client_secret",
        "cloud",
        re.compile(r"\bp8e-[A-Za-z0-9]{32}\b", re.I),
        "high",
    ),
    Rule(
        "alibaba_access_key",
        "cloud",
        re.compile(r"\bLTAI[A-Za-z0-9]{20}\b", re.I),
        "high",
    ),
    Rule(
        "artifactory_api_key",
        "registry",
        re.compile(r"\bAKCp[A-Za-z0-9]{69}\b"),
        "high",
    ),
    Rule(
        "artifactory_reference",
        "registry",
        re.compile(r"\bcmVmd[A-Za-z0-9]{59}\b"),
        "medium",
    ),
    Rule(
        "atlassian_api_token",
        "productivity",
        re.compile(r"\bATATT3[A-Za-z0-9_=-]{186}\b"),
        "high",
    ),
    Rule(
        "authress_access_key",
        "auth",
        re.compile(
            r"\b(?:sc|ext|scauth|authress)_"
            r"[A-Za-z0-9]{5,30}\."
            r"[A-Za-z0-9]{4,6}\."
            r"acc[_-][A-Za-z0-9-]{10,32}\."
            r"[A-Za-z0-9+/_=-]{30,120}"
        ),
        "high",
    ),
    Rule(
        "aws_bedrock_api_key",
        "cloud",
        re.compile(r"\bABSK[A-Za-z0-9+/]{109,269}={0,2}"),
        "high",
    ),
    Rule(
        "azure_ad_client_secret",
        "cloud",
        re.compile(
            r"\b[A-Za-z0-9_~.]{3}\dQ~"
            r"[A-Za-z0-9_~.-]{31,34}\b"
        ),
        "high",
    ),
    Rule(
        "clojars",
        "registry",
        re.compile(r"\bCLOJARS_[a-z0-9]{60}\b", re.I),
        "high",
    ),
    Rule(
        "digitalocean_refresh",
        "cloud",
        re.compile(r"\bdor_v1_[A-Fa-f0-9]{64}\b"),
        "high",
    ),
    Rule(
        "dropbox_short_lived",
        "storage",
        re.compile(r"\bsl\.[A-Za-z0-9=_-]{135}\b"),
        "high",
    ),
    Rule(
        "dynatrace",
        "monitoring",
        re.compile(
            r"\bdt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b",
            re.I,
        ),
        "high",
    ),
    Rule(
        "easypost_live",
        "shipping",
        re.compile(r"\bEZAK[A-Za-z0-9]{54}\b", re.I),
        "high",
    ),
    Rule(
        "easypost_test",
        "shipping",
        re.compile(r"\bEZTK[A-Za-z0-9]{54}\b", re.I),
        "high",
    ),
    Rule(
        "flyio",
        "cloud",
        re.compile(
            r"\b(?:"
            r"fo1_[A-Za-z0-9_-]{43}|"
            r"fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|"
            r"fm2_[A-Za-z0-9+/]{100,}={0,3}"
            r")"
        ),
        "high",
    ),
    Rule(
        "frameio",
        "media",
        re.compile(r"\bfio-u-[A-Za-z0-9=_-]{64}\b", re.I),
        "high",
    ),
    Rule(
        "vault_batch",
        "secrets",
        re.compile(r"\bhvb\.[A-Za-z0-9_-]{138,300}\b"),
        "high",
    ),
    Rule(
        "vault_service",
        "secrets",
        re.compile(r"\bhvs\.[A-Za-z0-9_-]{90,120}\b"),
        "high",
    ),
    Rule(
        "heroku_v2",
        "cloud",
        re.compile(r"\bHRKU-AA[A-Za-z0-9_-]{58}\b"),
        "high",
    ),
    Rule(
        "postman",
        "api",
        re.compile(r"\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}\b"),
        "high",
    ),
    Rule(
        "prefect",
        "automation",
        re.compile(r"\bpnu_[A-Za-z0-9]{36}\b"),
        "high",
    ),
    Rule(
        "pulumi",
        "cloud",
        re.compile(r"\bpul-[A-Fa-f0-9]{40}\b"),
        "high",
    ),
    Rule(
        "readme",
        "documentation",
        re.compile(r"\brdme_[A-Za-z0-9]{70}\b", re.I),
        "high",
    ),
    Rule(
        "rubygems",
        "registry",
        re.compile(r"\brubygems_[A-Fa-f0-9]{48}\b"),
        "high",
    ),
    Rule(
        "sourcegraph",
        "code_search",
        re.compile(
            r"\b(?:"
            r"sgp_(?:[A-Fa-f0-9]{16}|local)_[A-Fa-f0-9]{40}|"
            r"sgp_[A-Fa-f0-9]{40}"
            r")\b"
        ),
        "high",
    ),
    Rule(
        "terraform_cloud",
        "cloud",
        re.compile(
            r"\b[A-Za-z0-9]{14}\.atlasv1\."
            r"[A-Za-z0-9=_-]{60,70}\b",
            re.I,
        ),
        "high",
    ),
    Rule(
        "supabase_secret",
        "data",
        re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "supabase_pat",
        "data",
        re.compile(r"\bsbp_[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "tailscale",
        "network",
        re.compile(r"\btskey-(?:api|auth)-[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    Rule(
        "slack_app",
        "chat",
        re.compile(r"\bxapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+\b"),
        "high",
    ),
    Rule(
        "paseto",
        "token",
        re.compile(
            r"\bv[1-4]\.(?:local|public)\."
            r"[A-Za-z0-9_-]{40,}"
            r"(?:\.[A-Za-z0-9_-]+)?\b"
        ),
        "high",
    ),
    Rule(
        "jwe",
        "token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]*\."
            r"[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\."
            r"[A-Za-z0-9_-]{8,}\b"
        ),
        "high",
    ),
    Rule(
        "discord_bot",
        "chat",
        re.compile(
            r"\b(?:M|N|O)[A-Za-z0-9_-]{23,27}\."
            r"[A-Za-z0-9_-]{6}\."
            r"[A-Za-z0-9_-]{27,}\b"
        ),
        "high",
    ),
    Rule(
        "telegram_bot",
        "chat",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        "medium",
    ),
    Rule(
        "jwt",
        "token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\."
            r"eyJ[A-Za-z0-9_-]{10,}\."
            r"(?:[A-Za-z0-9_-]{5,})?"
        ),
        "high",
    ),
    Rule(
        "openai_legacy",
        "llm",
        re.compile(
            r"\bsk-"
            r"(?!ant-|proj-|svcacct-|admin-|or-)"
            r"[A-Za-z0-9_-]{32,48}\b"
        ),
        "medium",
    ),
    Rule(
        "stripe_webhook_secret",
        "payments",
        re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b"),
        "high",
    ),
    Rule(
        "sendinblue",
        "email",
        re.compile(
            r"\bxkeysib-[A-Fa-f0-9]{64}-[A-Za-z0-9]{16}\b"
        ),
        "high",
    ),
    Rule(
        "gitlab_cicd_job",
        "vcs",
        re.compile(
            r"\bglcbt-[A-Za-z0-9]{1,5}_[A-Za-z0-9_-]{20}\b"
        ),
        "high",
    ),
    Rule(
        "gitlab_deploy",
        "vcs",
        re.compile(r"\bgldt-[A-Za-z0-9_-]{20}\b"),
        "high",
    ),
    Rule(
        "gitlab_feature_flag",
        "vcs",
        re.compile(r"\bglffct-[A-Za-z0-9_-]{20}\b"),
        "high",
    ),
    Rule(
        "gitlab_feed",
        "vcs",
        re.compile(r"\bglft-[A-Za-z0-9_-]{20}\b"),
        "high",
    ),
    Rule(
        "gitlab_incoming_mail",
        "vcs",
        re.compile(r"\bglimt-[A-Za-z0-9_-]{25}\b"),
        "high",
    ),
    Rule(
        "gitlab_agent",
        "vcs",
        re.compile(r"\bglagent-[A-Za-z0-9_-]{50}\b"),
        "high",
    ),
    Rule(
        "gitlab_oauth_secret",
        "vcs",
        re.compile(r"\bgloas-[A-Za-z0-9_-]{64}\b"),
        "high",
    ),
    Rule(
        "gitlab_pipeline_trigger",
        "vcs",
        re.compile(r"\bglptt-[A-Fa-f0-9]{40}\b"),
        "high",
    ),
    Rule(
        "gitlab_runner",
        "vcs",
        re.compile(r"\bglrt-[A-Za-z0-9_-]{20}\b"),
        "high",
    ),
    Rule(
        "gitlab_scim",
        "vcs",
        re.compile(r"\bglsoat-[A-Za-z0-9_-]{20}\b"),
        "high",
    ),
    Rule(
        "slack_webhook",
        "webhook",
        re.compile(
            r"https://hooks\.slack\.com/(?:"
            r"services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25}|"
            r"workflows/T[A-Z0-9]+/A[A-Z0-9]+/"
            r"\d{17,19}/[A-Za-z0-9]{23,25}|"
            r"triggers/[A-Za-z0-9+/]{43,56}"
            r")"
        ),
        "high",
    ),
    Rule(
        "discord_webhook",
        "webhook",
        re.compile(
            r"https?://(?:discord|discordapp)\.com/api/webhooks/"
            r"\d{18,19}/[A-Za-z0-9_-]{60,80}"
        ),
        "high",
    ),
    Rule(
        "tines_webhook",
        "webhook",
        re.compile(
            r"https://[A-Za-z0-9-]+\.tines\.com/webhook/"
            r"[A-Fa-f0-9]{32}/[A-Fa-f0-9]{32}"
        ),
        "high",
    ),
    Rule(
        "teams_webhook",
        "webhook",
        re.compile(
            r"https?://[A-Za-z0-9.-]*"
            r"(?:webhook\.office\.com|webhook\.office365\.com)/"
            r"webhookb2/[A-Za-z0-9@._/%?=&+-]{40,}"
        ),
        "high",
    ),
]


CONTEXT_RULES: List[Rule] = [
    Rule(
        "mui_license",
        "license",
        re.compile(
            r"(?<![A-Za-z0-9+/=_-])"
            r"[A-Za-z0-9+/=_-]{80,200}"
            r"(?![A-Za-z0-9+/=_-])"
        ),
        "medium",
        keywords(
            "materialuilicense",
            "material_ui_license",
            "material-ui",
            "mui x",
            "mui_license",
            "licensekey",
            "license_key",
            "setlicensekey",
            "x-license",
        ),
    ),
    Rule(
        "surfly",
        "widget",
        re.compile(
            r"\b(?:"
            r"[A-Fa-f0-9]{32}|"
            r"[A-Fa-f0-9]{8}"
            r"(?:-[A-Fa-f0-9]{4}){3}"
            r"-[A-Fa-f0-9]{12}"
            r")\b"
        ),
        "medium",
        keywords(
            "surfly",
            "surflykey",
            "surfly_key",
        ),
    ),
    Rule(
        "contentful_delivery",
        "cms",
        re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"[A-Za-z0-9_-]{43}"
            r"(?![A-Za-z0-9_-])"
        ),
        "medium",
        keywords(
            "contentful",
            "contentfulaccesstoken",
            "contentful_access_token",
            "cda_token",
            "previewaccesstoken",
        ),
    ),
    Rule(
        "algolia",
        "search",
        re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        "medium",
        keywords(
            "algolia",
            "algoliasearch",
            "searchonlyapikey",
            "adminapikey",
        ),
    ),
    Rule(
        "datadog",
        "monitoring",
        re.compile(r"\b[A-Fa-f0-9]{32,40}\b"),
        "medium",
        keywords(
            "datadog",
            "dd_api_key",
            "dd-api-key",
            "dd_app_key",
        ),
    ),
    Rule(
        "launchdarkly",
        "feature_flags",
        re.compile(
            r"(?<![A-Za-z0-9=_-])"
            r"[A-Za-z0-9=_-]{24,64}"
            r"(?![A-Za-z0-9=_-])"
        ),
        "medium",
        keywords(
            "launchdarkly",
            "launch_darkly",
            "ld_sdk",
            "ldclient",
        ),
    ),
    Rule(
        "segment",
        "analytics",
        re.compile(r"\b[A-Za-z0-9]{32}\b"),
        "medium",
        keywords(
            "segmentwritekey",
            "segment_write_key",
            "segmentkey",
            "segment.io",
            "analytics.js",
        ),
    ),
    Rule(
        "posthog_named",
        "analytics",
        re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"[A-Za-z0-9_-]{20,80}"
            r"(?![A-Za-z0-9_-])"
        ),
        "medium",
        keywords(
            "posthogkey",
            "posthog_key",
            "posthogapikey",
            "posthog_api_key",
        ),
    ),
    Rule(
        "cloudflare",
        "cloud",
        re.compile(r"\b[A-Fa-f0-9]{37,40}\b"),
        "medium",
        keywords(
            "cloudflare",
            "cf_api_token",
            "cfapitoken",
        ),
    ),
    Rule(
        "auth0",
        "auth",
        re.compile(
            r"(?<![A-Za-z0-9_-])"
            r"[A-Za-z0-9_-]{32,64}"
            r"(?![A-Za-z0-9_-])"
        ),
        "medium",
        keywords(
            "auth0",
            "clientsecret",
            "client_secret",
        ),
    ),
    Rule(
        "okta",
        "auth",
        re.compile(r"\b00[A-Za-z0-9_-]{38,50}\b"),
        "medium",
        keywords(
            "okta",
            "okta_token",
            "apitoken",
        ),
    ),
    Rule(
        "cohere",
        "llm",
        re.compile(r"\b[A-Za-z0-9]{40}\b"),
        "medium",
        keywords("cohere"),
    ),
    Rule(
        "mistral",
        "llm",
        re.compile(r"\b[A-Za-z0-9]{32}\b"),
        "medium",
        keywords("mistral"),
    ),
    Rule(
        "elevenlabs",
        "audio",
        re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        "medium",
        keywords(
            "elevenlabs",
            "eleven_labs",
        ),
    ),
    Rule(
        "together",
        "llm",
        re.compile(r"\b[A-Fa-f0-9]{64}\b"),
        "medium",
        keywords(
            "together",
            "togetherai",
        ),
    ),
    Rule(
        "cerebras",
        "llm",
        re.compile(r"\b[A-Za-z0-9]{40,}\b"),
        "medium",
        keywords("cerebras"),
    ),
    Rule(
        "deepseek",
        "llm",
        re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"),
        "high",
        keywords("deepseek"),
    ),
    Rule(
        "twilio",
        "comms",
        re.compile(r"\bSK[A-Fa-f0-9]{32}\b"),
        "medium",
        keywords(
            "twilio",
            "account_sid",
            "authtoken",
        ),
    ),
    Rule(
        "adafruit",
        "iot",
        re.compile(r"\b[A-Za-z0-9_-]{32}\b"),
        "medium",
        keywords(
            "adafruit",
            "adafruitio",
            "aio_key",
        ),
    ),
    Rule(
        "adobe_client_id",
        "cloud",
        re.compile(r"\b[A-Fa-f0-9]{32}\b"),
        "medium",
        keywords(
            "adobe",
            "adobeio",
            "client_id",
        ),
    ),
    Rule(
        "alibaba_secret",
        "cloud",
        re.compile(r"\b[A-Za-z0-9]{30}\b"),
        "medium",
        keywords(
            "alibaba",
            "aliyun",
            "accesskeysecret",
        ),
    ),
    Rule(
        "asana_secret",
        "productivity",
        re.compile(r"\b[A-Za-z0-9]{32}\b"),
        "medium",
        keywords(
            "asana",
            "client_secret",
        ),
    ),
    Rule(
        "beamer",
        "analytics",
        re.compile(r"\bb_[A-Za-z0-9=_-]{44}\b"),
        "medium",
        keywords("beamer"),
    ),
    Rule(
        "bitbucket_secret",
        "vcs",
        re.compile(r"\b[A-Za-z0-9=_-]{64}\b"),
        "medium",
        keywords(
            "bitbucket",
            "client_secret",
        ),
    ),
    Rule(
        "codecov",
        "code_quality",
        re.compile(r"\b[A-Za-z0-9]{32}\b"),
        "medium",
        keywords(
            "codecov",
            "codecov_token",
        ),
    ),
    Rule(
        "confluent_access",
        "data",
        re.compile(r"\b[A-Za-z0-9]{16}\b"),
        "medium",
        keywords(
            "confluent",
            "confluent_key",
        ),
    ),
    Rule(
        "confluent_secret",
        "data",
        re.compile(r"\b[A-Za-z0-9]{64}\b"),
        "medium",
        keywords(
            "confluent",
            "confluent_secret",
        ),
    ),
    Rule(
        "fastly",
        "cdn",
        re.compile(r"\b[A-Za-z0-9=_-]{32}\b"),
        "medium",
        keywords(
            "fastly",
            "fastly_api_token",
        ),
    ),
    Rule(
        "heroku",
        "cloud",
        re.compile(
            r"\b[A-Fa-f0-9]{8}"
            r"(?:-[A-Fa-f0-9]{4}){3}"
            r"-[A-Fa-f0-9]{12}\b"
        ),
        "medium",
        keywords(
            "heroku",
            "heroku_api_key",
        ),
    ),
    Rule(
        "hubspot",
        "crm",
        re.compile(
            r"\b[A-Fa-f0-9]{8}"
            r"(?:-[A-Fa-f0-9]{4}){3}"
            r"-[A-Fa-f0-9]{12}\b"
        ),
        "medium",
        keywords(
            "hubspot",
            "hapikey",
        ),
    ),
    Rule(
        "kraken",
        "finance",
        re.compile(
            r"(?<![A-Za-z0-9+/=_-])"
            r"[A-Za-z0-9+/=_-]{80,90}"
            r"(?![A-Za-z0-9+/=_-])"
        ),
        "medium",
        keywords(
            "kraken",
            "kraken_api",
        ),
    ),
    Rule(
        "lob",
        "mail",
        re.compile(
            r"\b(?:live|test)_(?:pub_)?[A-Fa-f0-9]{31,35}\b"
        ),
        "medium",
        keywords(
            "lob",
            "lob_api",
        ),
    ),
    Rule(
        "mailchimp",
        "email",
        re.compile(r"\b[A-Fa-f0-9]{32}-us\d{2}\b", re.I),
        "medium",
        keywords(
            "mailchimp",
            "mailchimpsdk.initialize",
        ),
    ),
    Rule(
        "messagebird",
        "comms",
        re.compile(r"\b[A-Za-z0-9]{25}\b"),
        "medium",
        keywords(
            "messagebird",
            "message_bird",
            "message-bird",
        ),
    ),
    Rule(
        "netlify",
        "cloud",
        re.compile(r"\b[A-Za-z0-9=_-]{40,46}\b"),
        "medium",
        keywords(
            "netlify",
            "netlify_token",
        ),
    ),
    Rule(
        "snyk",
        "security",
        re.compile(
            r"\b[A-Fa-f0-9]{8}"
            r"(?:-[A-Fa-f0-9]{4}){3}"
            r"-[A-Fa-f0-9]{12}\b"
        ),
        "medium",
        keywords(
            "snyk",
            "snyk_token",
        ),
    ),
    Rule(
        "mongodb_atlas",
        "data",
        re.compile(r"\b[A-Za-z0-9]{38,42}\b"),
        "medium",
        keywords(
            "mongodb",
            "mongo_db",
            "atlas",
            "public_key",
            "private_key",
        ),
    ),
    Rule(
        "pagerduty",
        "monitoring",
        re.compile(r"\b[A-Za-z0-9_-]{20}\b"),
        "medium",
        keywords(
            "pagerduty",
            "pager_duty",
            "pd_api_token",
        ),
    ),
    Rule(
        "aws_secret_access_key",
        "cloud",
        re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
        "medium",
        keywords(
            "aws_secret_access_key",
            "secretaccesskey",
            "awssecret",
        ),
    ),
    Rule(
        "azure_storage_key",
        "cloud",
        re.compile(r"\b[A-Za-z0-9+/]{86}==\b"),
        "medium",
        keywords(
            "accountkey",
            "azure_storage",
            "storageaccountkey",
        ),
    ),
    Rule(
        "firebase_fcm_server_key",
        "cloud",
        re.compile(
            r"\bAAAA[A-Za-z0-9_-]{7}:"
            r"[A-Za-z0-9_-]{100,200}\b"
        ),
        "medium",
        keywords(
            "firebase",
            "fcm",
            "serverkey",
            "server_key",
        ),
    ),
]


STRUCTURED_RULES: List[Rule] = [
    Rule(
        "authorization_bearer",
        "auth",
        re.compile(
            r'''(?ix)
            (?:authorization|proxy[-_]?authorization)
            \s*["'`]?\s*[:=]\s*["'`]
            \s*(?:bearer|token)\s+
            ([A-Za-z0-9_~.+/=-]{16,500})
            ["'`]
            '''
        ),
        "high",
        None,
        1,
    ),
    Rule(
        "authorization_basic",
        "auth",
        re.compile(
            r'''(?ix)
            (?:authorization|proxy[-_]?authorization)
            \s*["'`]?\s*[:=]\s*["'`]
            \s*basic\s+
            ([A-Za-z0-9+/]{8,}={0,3})
            ["'`]
            '''
        ),
        "high",
        None,
        1,
    ),
    Rule(
        "hardcoded_api_header",
        "auth",
        re.compile(
            r'''(?ix)
            (?:
                x[-_]?api[-_]?key|
                api[-_]?key|
                x[-_]?auth[-_]?token|
                x[-_]?access[-_]?token|
                x[-_]?client[-_]?secret
            )
            \s*["'`]?\s*[:=]\s*["'`]
            ([A-Za-z0-9_~.+/=-]{16,300})
            ["'`]
            '''
        ),
        "medium",
        None,
        1,
    ),
    Rule(
        "database_uri_password",
        "database",
        re.compile(
            r'''(?ix)
            \b
            (?:
                mongodb(?:\+srv)?|
                postgres(?:ql)?|
                mysql|
                mariadb|
                redis(?:s)?|
                amqp(?:s)?
            )
            ://
            [^:@/\s"'`]{1,128}
            :
            ([^@/\s"'`]{3,256})
            @
            [^\s"'`]{1,512}
            '''
        ),
        "high",
        None,
        1,
    ),
    Rule(
        "url_basic_password",
        "auth",
        re.compile(
            r'''(?ix)
            \bhttps?://
            [^:@/\s"'`]{1,128}
            :
            ([^@/\s"'`]{3,256})
            @
            [A-Za-z0-9.-]+
            (?::\d{1,5})?
            (?:/[^\s"'`]*)?
            '''
        ),
        "medium",
        None,
        1,
    ),
    Rule(
        "azure_redis_password",
        "database",
        re.compile(
            r'''(?ix)
            \b
            [A-Za-z0-9.-]+
            \.redis\.cache\.windows\.net:6380,
            password=([^,\s"'`]{20,100}),
            ssl=true,
            abortconnect=false
            '''
        ),
        "high",
        None,
        1,
    ),
]


GENERIC_ASSIGN_RE = re.compile(
    r'''(?ix)
    (?P<name>
        [A-Za-z0-9_.-]{0,50}
        (?:
            api[_-]?key|
            secret|
            token|
            access[_-]?key|
            client[_-]?secret|
            authorization|
            bearer
        )
    )
    \s*[:=]\s*
    ["']
    (?P<value>[A-Za-z0-9_./+\-=]{20,200})
    ["']
    '''
)

CONCAT_RE = re.compile(
    r'''(?x)
    (?:
        ["'][A-Za-z0-9_./+\-=]{1,32}["']
        \s*\+\s*
    ){2,}
    ["'][A-Za-z0-9_./+\-=]{1,32}["']
    '''
)

HEX_ESCAPE_RE = re.compile(
    r"(?:\\x[0-9A-Fa-f]{2}){8,}"
)

UNICODE_ESCAPE_RE = re.compile(
    r"(?:\\u[0-9A-Fa-f]{4}){6,}"
)

B64_RE = re.compile(
    r"(?<![A-Za-z0-9+/_-])"
    r"[A-Za-z0-9+/_-]{40,}={0,2}"
    r"(?![A-Za-z0-9+/_-])"
)

SCRIPT_RE = re.compile(
    r'''<script[^>]+src=["']([^"']+)["']''',
    re.I,
)

JS_LINK_RE = re.compile(
    r'''["']([^"'\s]{1,400}\.(?:js|mjs)(?:\?[^"']*)?)["']''',
    re.I,
)

SOURCEMAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL=([^\s]+)"
)

INLINE_MAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL="
    r"data:application/json"
    r"(?:;charset=[^;,]+)?;"
    r"(base64),([^\s]+)"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts: Dict[str, int] = {}

    for char in value:
        counts[char] = counts.get(char, 0) + 1

    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def entropy_ratio(value: str) -> float:
    alphabet = 0

    alphabet += 26 if re.search(r"[a-z]", value) else 0
    alphabet += 26 if re.search(r"[A-Z]", value) else 0
    alphabet += 10 if re.search(r"\d", value) else 0
    alphabet += 10 if re.search(r"[^A-Za-z0-9]", value) else 0

    return shannon_entropy(value) / math.log2(max(alphabet, 2))


PLACEHOLDER_EXACT = {
    "true",
    "false",
    "null",
    "undefined",
    "none",
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "test",
    "testing",
    "development",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "dummy",
    "sample",
    "lorem",
    "your_key",
    "your_token",
    "your_secret",
}

PLACEHOLDER_BODY_RE = re.compile(
    r"(?i)^"
    r"(?:"
    r"example|placeholder|changeme|change_me|replace_me|"
    r"dummy|sample|lorem"
    r")"
    r"(?:[-_.]?(?:api)?(?:key|token|secret|password|value))?"
    r"$"
)

CONTENT_HASH_RE = re.compile(
    r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$",
    re.I,
)

PATHLIKE_RE = re.compile(
    r"^[./]|"
    r"/.+\.[A-Za-z0-9]{1,5}$|"
    r"://|"
    r"\.(?:"
    r"js|mjs|css|png|jpe?g|gif|svg|woff2?|ttf|map|"
    r"html?|json|xml|txt"
    r")\b",
    re.I,
)

SEMVER_RE = re.compile(
    r"^v?\d+(?:\.\d+){1,3}[A-Za-z0-9.\-+]*$"
)


def is_placeholder_secret(value: str) -> bool:
    try:
        decoded_value = unquote(value)
    except (TypeError, ValueError):
        decoded_value = value

    normalized = decoded_value.strip().strip("\"'`")
    lowered = normalized.lower()

    if not normalized or lowered in PLACEHOLDER_EXACT:
        return True

    if PLACEHOLDER_BODY_RE.fullmatch(normalized):
        return True

    if re.search(
        r"\$\{[^}]+\}|"
        r"\{\{[^}]+\}\}|"
        r"<[A-Za-z0-9_-]+>",
        normalized,
    ):
        return True

    if re.fullmatch(
        r"(?:[xX*._-]{6,}|0{12,}|1{12,})",
        normalized,
    ):
        return True

    return False


def low_quality(value: str, minimum: float) -> bool:
    if is_placeholder_secret(value):
        return True

    if len(set(value)) < 6:
        return True

    if re.fullmatch(r"(.)\1{4,}", value):
        return True

    if SEMVER_RE.match(value):
        return True

    return entropy_ratio(value) < minimum


def is_probable_secret(value: str) -> bool:
    if len(value) < 20:
        return False

    if low_quality(value, 0.62):
        return False

    if PATHLIKE_RE.search(value):
        return False

    if CONTENT_HASH_RE.match(value):
        return False

    if (
        value.count(".") >= 2
        and not value.startswith(("sk", "pk", "ey", "AIza"))
    ):
        return False

    has_digit = bool(re.search(r"\d", value))
    has_symbol = bool(re.search(r"[+/=_.\-]", value))

    character_classes = sum(
        bool(re.search(pattern, value))
        for pattern in (
            r"[a-z]",
            r"[A-Z]",
            r"\d",
            r"[^A-Za-z0-9]",
        )
    )

    return (
        character_classes >= 2
        and (
            has_digit
            or (has_symbol and len(value) >= 24)
        )
    )


def decode_base64url_json(value: str) -> Optional[dict]:
    try:
        decoded = base64.urlsafe_b64decode(
            (
                value
                + "=" * (-len(value) % 4)
            ).encode()
        )

        parsed = json.loads(
            decoded.decode("utf-8")
        )

        if isinstance(parsed, dict):
            return parsed

    except (
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        pass

    return None


def valid_jwt(value: str) -> bool:
    parts = value.split(".")

    if len(parts) != 3:
        return False

    if not parts[0] or not parts[1]:
        return False

    header = decode_base64url_json(parts[0])
    payload = decode_base64url_json(parts[1])

    return bool(
        header
        and payload is not None
        and "alg" in header
    )


def valid_jwe(value: str) -> bool:
    parts = value.split(".")

    if len(parts) != 5:
        return False

    if not parts[0]:
        return False

    if not all(
        parts[index]
        for index in (2, 3, 4)
    ):
        return False

    header = decode_base64url_json(parts[0])

    return bool(
        header
        and "alg" in header
        and "enc" in header
    )


def valid_paseto(value: str) -> bool:
    parts = value.split(".")

    if len(parts) not in (3, 4):
        return False

    if parts[0] not in {
        "v1",
        "v2",
        "v3",
        "v4",
    }:
        return False

    if parts[1] not in {
        "local",
        "public",
    }:
        return False

    if not parts[2]:
        return False

    minimum_decoded = {
        ("v1", "local"): 80,
        ("v2", "local"): 40,
        ("v3", "local"): 80,
        ("v4", "local"): 64,
        ("v1", "public"): 64,
        ("v2", "public"): 64,
        ("v3", "public"): 64,
        ("v4", "public"): 64,
    }[(parts[0], parts[1])]

    try:
        decoded = base64.urlsafe_b64decode(
            (
                parts[2]
                + "=" * (-len(parts[2]) % 4)
            ).encode()
        )
    except (
        ValueError,
        binascii.Error,
    ):
        return False

    return len(decoded) >= minimum_decoded


def valid_basic_auth(value: str) -> bool:
    try:
        decoded = base64.b64decode(
            value,
            validate=True,
        ).decode("utf-8")

    except (
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
    ):
        return False

    if ":" not in decoded:
        return False

    username, password = decoded.split(":", 1)

    return bool(
        username
        and password
        and not is_placeholder_secret(password)
    )


def redact(value: str) -> str:
    if len(value) <= 12:
        return (
            value[:2]
            + "*" * max(0, len(value) - 2)
        )

    return (
        f"{value[:4]}..."
        f"{value[-4:]} "
        f"(len={len(value)})"
    )


def line_column(
    text: str,
    offset: int,
) -> Tuple[int, int]:
    line = text.count(
        "\n",
        0,
        offset,
    ) + 1

    previous = text.rfind(
        "\n",
        0,
        offset,
    )

    column = (
        offset + 1
        if previous < 0
        else offset - previous
    )

    return line, column


def context_snippet(
    text: str,
    start: int,
    end: int,
    width: int = 35,
) -> str:
    snippet = (
        text[max(0, start - width):start]
        + "«TOKEN»"
        + text[end:min(len(text), end + width)]
    )

    return re.sub(
        r"\s+",
        " ",
        snippet,
    ).strip()[:160]


def severity(
    provider: str,
    confidence: str,
) -> str:
    critical = {
        "openai",
        "openrouter",
        "anthropic",
        "aws_access_key",
        "github",
        "github_fine_grained",
        "stripe_restricted",
        "stripe_or_clerk_secret",
    }

    if (
        confidence == "high"
        and provider in critical
    ):
        return "critical"

    if confidence == "high":
        return "high"

    if confidence == "medium":
        return "medium"

    return "low"


@dataclass
class Finding:
    provider: str
    category: str
    confidence: str
    severity: str
    source: str
    line: Optional[int]
    column: Optional[int]
    transform: str
    context: str
    redacted: str
    finding_id: str
    _token: str = field(
        default="",
        repr=False,
    )

    def record(
        self,
        include_token: bool = False,
    ) -> dict:
        result = {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "provider": self.provider,
            "category": self.category,
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "transform": self.transform,
            "redacted": self.redacted,
            "context": self.context,
        }

        if include_token:
            result["token"] = self._token

        return result


@dataclass
class Candidate:
    rule: Rule
    token: str
    text: str
    start: int
    end: int
    transform: str


@dataclass
class Config:
    scope: List[str]
    threads: int = DEFAULT_THREADS
    timeout: int = DEFAULT_TIMEOUT
    max_bytes: int = DEFAULT_MAX_BYTES
    max_urls: int = DEFAULT_MAX_URLS
    max_depth: int = DEFAULT_MAX_DEPTH
    min_entropy: float = DEFAULT_MIN_ENTROPY
    follow: bool = True
    decode: bool = True
    generic: bool = False


def decoded_with_context(
    text: str,
    start: int,
    end: int,
    decoded: str,
    width: int = 220,
) -> str:
    return (
        text[max(0, start - width):start]
        + decoded
        + text[end:min(len(text), end + width)]
    )


def decoded_segments(
    text: str,
) -> Iterable[Tuple[str, str]]:
    for match in B64_RE.finditer(text):
        blob = match.group(0)

        decoders = (
            ("base64", base64.b64decode),
            ("base64url", base64.urlsafe_b64decode),
        )

        for label, decoder in decoders:
            try:
                padded = (
                    blob
                    + "=" * (-len(blob) % 4)
                )

                raw = decoder(padded.encode())
                decoded = raw.decode("utf-8")

                printable_ratio = (
                    sum(
                        char.isprintable()
                        for char in decoded
                    )
                    / len(decoded)
                    if decoded
                    else 0
                )

                if (
                    decoded
                    and printable_ratio >= 0.85
                ):
                    yield (
                        label,
                        decoded_with_context(
                            text,
                            match.start(),
                            match.end(),
                            decoded,
                        ),
                    )

            except (
                ValueError,
                UnicodeDecodeError,
                binascii.Error,
            ):
                pass

    for match in HEX_ESCAPE_RE.finditer(text):
        try:
            decoded = bytes(
                int(part, 16)
                for part in re.findall(
                    r"\\x([0-9A-Fa-f]{2})",
                    match.group(),
                )
            ).decode()

            yield (
                "hex_escape",
                decoded_with_context(
                    text,
                    match.start(),
                    match.end(),
                    decoded,
                ),
            )

        except (
            ValueError,
            UnicodeDecodeError,
        ):
            pass

    for match in UNICODE_ESCAPE_RE.finditer(text):
        try:
            decoded = "".join(
                chr(int(part, 16))
                for part in re.findall(
                    r"\\u([0-9A-Fa-f]{4})",
                    match.group(),
                )
            )

            yield (
                "unicode_escape",
                decoded_with_context(
                    text,
                    match.start(),
                    match.end(),
                    decoded,
                ),
            )

        except ValueError:
            pass

    for match in CONCAT_RE.finditer(text):
        decoded = "".join(
            re.findall(
                r'''["']([^"']*)["']''',
                match.group(),
            )
        )

        yield (
            "concatenation",
            decoded_with_context(
                text,
                match.start(),
                match.end(),
                decoded,
            ),
        )


def finding_key(
    token: str,
    source: str,
) -> str:
    return hashlib.sha256(
        (
            source
            + "\0"
            + token
        ).encode("utf-8")
    ).hexdigest()[:16]


def normalize_scope(value: str) -> str:
    value = value.strip().lower().rstrip(".")

    if "://" in value:
        value = urlparse(value).hostname or ""

    return value.split(":", 1)[0]


def host_in_scope(
    url: str,
    scopes: List[str],
) -> bool:
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.hostname:
        return False

    host = parsed.hostname.lower().rstrip(".")

    return any(
        host == scope
        or host.endswith("." + scope)
        for scope in scopes
    )


def canonical_url(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            f"invalid URL port in {url!r}"
        ) from error

    netloc = host

    if (
        port
        and not (
            (
                parsed.scheme == "http"
                and port == 80
            )
            or (
                parsed.scheme == "https"
                and port == 443
            )
        )
    ):
        netloc = f"{host}:{port}"

    path = parsed.path or "/"

    return urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.params,
            parsed.query,
            "",
        )
    )


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, scopes: List[str]):
        super().__init__()
        self.scopes = scopes

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        target = urljoin(
            req.full_url,
            newurl,
        )

        if not host_in_scope(
            target,
            self.scopes,
        ):
            raise HTTPError(
                target,
                code,
                "redirect left authorized scope",
                headers,
                fp,
            )

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            target,
        )


def decompress_limited(
    raw: bytes,
    encoding: str,
    limit: int,
) -> bytes:
    encoding = encoding.lower().strip()

    if (
        not encoding
        or encoding == "identity"
    ):
        return raw[:limit]

    window_bits = (
        16 + zlib.MAX_WBITS
        if "gzip" in encoding
        else zlib.MAX_WBITS
    )

    try:
        decompressor = zlib.decompressobj(
            window_bits
        )

        data = decompressor.decompress(
            raw,
            limit + 1,
        )

    except zlib.error:
        if "deflate" not in encoding:
            raise

        decompressor = zlib.decompressobj(
            -zlib.MAX_WBITS
        )

        data = decompressor.decompress(
            raw,
            limit + 1,
        )

    if (
        len(data) > limit
        or decompressor.unconsumed_tail
    ):
        raise ValueError(
            "decompressed response exceeds size limit"
        )

    return data


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    text: str
    content_type: str


def fetch(
    url: str,
    config: Config,
) -> Optional[FetchResult]:
    if not host_in_scope(
        url,
        config.scope,
    ):
        log(f"[scope] skipped {url}")
        return None

    opener = build_opener(
        ScopedRedirectHandler(config.scope)
    )

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,"
                "application/javascript,"
                "text/javascript,"
                "application/json,"
                "*/*;q=0.2"
            ),
            "Accept-Encoding": (
                "gzip, deflate, identity"
            ),
        },
    )

    for attempt in range(MAX_RETRIES + 1):
        try:
            with opener.open(
                request,
                timeout=config.timeout,
            ) as response:
                final_url = canonical_url(
                    response.geturl()
                )

                if not host_in_scope(
                    final_url,
                    config.scope,
                ):
                    log(
                        "[scope] blocked redirected "
                        f"response {final_url}"
                    )
                    return None

                raw = response.read(
                    config.max_bytes + 1
                )

                if len(raw) > config.max_bytes:
                    log(
                        "[size] skipped response over "
                        f"{config.max_bytes} bytes: {url}"
                    )
                    return None

                try:
                    raw = decompress_limited(
                        raw,
                        response.headers.get(
                            "Content-Encoding",
                            "",
                        ),
                        config.max_bytes,
                    )

                except (
                    zlib.error,
                    ValueError,
                ):
                    log(
                        "[decode] skipped invalid or "
                        "oversized compressed response: "
                        f"{url}"
                    )
                    return None

                content_type = (
                    response.headers.get_content_type()
                    or "application/octet-stream"
                )

                charset = (
                    response.headers.get_content_charset()
                    or "utf-8"
                )

                return FetchResult(
                    requested_url=url,
                    final_url=final_url,
                    text=raw.decode(
                        charset,
                        "replace",
                    ),
                    content_type=content_type,
                )

        except HTTPError as error:
            if (
                error.code in RETRY_STATUS
                and attempt < MAX_RETRIES
            ):
                time.sleep(
                    1.25 * (attempt + 1)
                )
                continue

            log(f"[http {error.code}] {url}")
            return None

        except (
            URLError,
            TimeoutError,
            OSError,
            ValueError,
        ) as error:
            if attempt < MAX_RETRIES:
                time.sleep(
                    0.75 * (attempt + 1)
                )
                continue

            log(
                f"[fetch error] {url}: "
                f"{type(error).__name__}"
            )
            return None

    return None


def assignment_context(
    text: str,
    start: int,
    end: int,
) -> bool:
    quoted = (
        start > 0
        and end < len(text)
        and text[start - 1] in "\"'`"
        and text[end] == text[start - 1]
    )

    left = text[max(0, start - 140):start]

    assigned_or_called = bool(
        re.search(
            r"(?:[:=,(]|=>)\s*[\"'`]?$",
            left,
        )
    )

    return quoted and assigned_or_called


def scan_text(
    text: str,
    source: str,
    config: Config,
    transform: str = "raw",
) -> List[Finding]:
    segments: List[Tuple[str, str]] = [
        (transform, text)
    ]

    if config.decode:
        segments.extend(
            decoded_segments(text)
        )

    candidates: List[Candidate] = []

    for segment_transform, segment in segments:
        all_rules = (
            STRICT_RULES
            + CONTEXT_RULES
            + STRUCTURED_RULES
        )

        for rule in all_rules:
            for match in rule.regex.finditer(segment):
                try:
                    token = match.group(
                        rule.secret_group
                    )

                    token_start = match.start(
                        rule.secret_group
                    )

                    token_end = match.end(
                        rule.secret_group
                    )

                except (
                    IndexError,
                    AttributeError,
                ):
                    continue

                if not token:
                    continue

                if is_placeholder_secret(token):
                    continue

                if (
                    rule.provider == "jwt"
                    and not valid_jwt(token)
                ):
                    continue

                if (
                    rule.provider == "jwe"
                    and not valid_jwe(token)
                ):
                    continue

                if (
                    rule.provider == "paseto"
                    and not valid_paseto(token)
                ):
                    continue

                if (
                    rule.provider
                    == "authorization_basic"
                    and not valid_basic_auth(token)
                ):
                    continue

                if rule.keywords:
                    statement = segment[
                        max(0, token_start - 180):
                        min(len(segment), token_end + 180)
                    ]

                    if not rule.keywords.search(statement):
                        continue

                    if not assignment_context(
                        segment,
                        token_start,
                        token_end,
                    ):
                        continue

                if (
                    rule.confidence != "high"
                    and low_quality(
                        token,
                        config.min_entropy,
                    )
                ):
                    continue

                candidates.append(
                    Candidate(
                        rule=rule,
                        token=token,
                        text=segment,
                        start=token_start,
                        end=token_end,
                        transform=segment_transform,
                    )
                )

        if config.generic:
            for match in GENERIC_ASSIGN_RE.finditer(
                segment
            ):
                token = match.group("value")

                if not is_probable_secret(token):
                    continue

                generic_rule = Rule(
                    provider=(
                        "generic:"
                        + match.group("name")[-32:]
                    ),
                    category="generic",
                    regex=GENERIC_ASSIGN_RE,
                    confidence="medium",
                )

                candidates.append(
                    Candidate(
                        rule=generic_rule,
                        token=token,
                        text=segment,
                        start=match.start("value"),
                        end=match.end("value"),
                        transform=segment_transform,
                    )
                )

    selected: Dict[str, Candidate] = {}

    for candidate in candidates:
        current = selected.get(
            candidate.token
        )

        if current is None:
            selected[candidate.token] = candidate
            continue

        candidate_rank = CONFIDENCE_ORDER[
            candidate.rule.confidence
        ]

        current_rank = CONFIDENCE_ORDER[
            current.rule.confidence
        ]

        if candidate_rank < current_rank:
            selected[candidate.token] = candidate

    findings: List[Finding] = []

    for candidate in selected.values():
        location_transforms = {
            "raw",
            "source_map_raw",
            "sourcesContent",
            "inline_source_map",
        }

        if candidate.transform in location_transforms:
            line, column = line_column(
                candidate.text,
                candidate.start,
            )
        else:
            line, column = None, None

        findings.append(
            Finding(
                provider=candidate.rule.provider,
                category=candidate.rule.category,
                confidence=candidate.rule.confidence,
                severity=severity(
                    candidate.rule.provider,
                    candidate.rule.confidence,
                ),
                source=source,
                line=line,
                column=column,
                transform=candidate.transform,
                context=context_snippet(
                    candidate.text,
                    candidate.start,
                    candidate.end,
                ),
                redacted=redact(
                    candidate.token
                ),
                finding_id=finding_key(
                    candidate.token,
                    source,
                ),
                _token=candidate.token,
            )
        )

    return findings


def source_map_documents(
    text: str,
    map_url: str,
) -> Iterable[Tuple[str, str]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return

    if not isinstance(document, dict):
        return

    sources = document.get("sources")
    contents = document.get("sourcesContent")

    if not isinstance(sources, list):
        return

    if not isinstance(contents, list):
        return

    source_root = (
        document.get("sourceRoot")
        if isinstance(
            document.get("sourceRoot"),
            str,
        )
        else ""
    )

    for index, content in enumerate(contents):
        if not isinstance(content, str):
            continue

        if not content:
            continue

        if (
            index < len(sources)
            and isinstance(sources[index], str)
        ):
            name = sources[index]
        else:
            name = f"source_{index}"

        yield (
            f"{map_url}#source={source_root}{name}",
            content,
        )


def source_map_referenced_urls(
    text: str,
    map_url: str,
    config: Config,
) -> Set[str]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return set()

    if not isinstance(document, dict):
        return set()

    sources = document.get("sources")

    if not isinstance(sources, list):
        return set()

    source_root = (
        document.get("sourceRoot")
        if isinstance(
            document.get("sourceRoot"),
            str,
        )
        else ""
    )

    discovered: Set[str] = set()

    for source in sources:
        if not isinstance(source, str):
            continue

        if not source:
            continue

        lowered_source = source.lower()
        lowered_root = source_root.lower()

        blocked_schemes = (
            "data:",
            "webpack:",
            "node:",
            "file:",
            "blob:",
        )

        if lowered_source.startswith(
            blocked_schemes
        ):
            continue

        if lowered_root.startswith(
            blocked_schemes
        ):
            continue

        reference = (
            urljoin(
                source_root.rstrip("/") + "/",
                source,
            )
            if source_root
            else source
        )

        try:
            candidate = canonical_url(
                urljoin(
                    map_url,
                    reference,
                )
            )
        except ValueError:
            continue

        if host_in_scope(
            candidate,
            config.scope,
        ):
            discovered.add(candidate)

    return discovered


def discover_urls(
    text: str,
    base_url: str,
    config: Config,
) -> Set[str]:
    discovered: Set[str] = set()

    for regex in (
        SCRIPT_RE,
        JS_LINK_RE,
        SOURCEMAP_RE,
    ):
        for match in regex.finditer(text):
            value = (
                match.group(1)
                .strip()
                .rstrip(";,'\"")
            )

            if value.startswith("data:"):
                continue

            try:
                candidate = canonical_url(
                    urljoin(
                        base_url,
                        value,
                    )
                )
            except ValueError:
                continue

            if host_in_scope(
                candidate,
                config.scope,
            ):
                discovered.add(candidate)

    parsed = urlparse(base_url)

    if (
        config.follow
        and parsed.path.lower().endswith(
            (".js", ".mjs")
        )
    ):
        map_path = parsed.path + ".map"

        try:
            candidate = canonical_url(
                urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        map_path,
                        parsed.params,
                        parsed.query,
                        "",
                    )
                )
            )
        except ValueError:
            candidate = ""

        if (
            candidate
            and host_in_scope(
                candidate,
                config.scope,
            )
        ):
            discovered.add(candidate)

    return discovered


def inline_source_maps(
    text: str,
    base_url: str,
) -> Iterable[Tuple[str, str]]:
    for index, match in enumerate(
        INLINE_MAP_RE.finditer(text),
        1,
    ):
        try:
            decoded = base64.b64decode(
                match.group(2)
            ).decode("utf-8")

            yield (
                f"{base_url}#inline-source-map-{index}",
                decoded,
            )

        except (
            ValueError,
            UnicodeDecodeError,
            binascii.Error,
        ):
            pass


def emit_finding(
    finding: Finding,
    live_handle,
    include_token: bool,
) -> None:
    location = finding.source

    if finding.line is not None:
        location += (
            f":{finding.line}:"
            f"{finding.column}"
        )

    log(
        f"[FOUND {finding.severity.upper():8}] "
        f"{finding.provider:22} "
        f"{finding.redacted:30} "
        f"{location}",
        stdout=True,
        always=True,
    )

    live_handle.write(
        json.dumps(
            finding.record(include_token),
            ensure_ascii=False,
        )
        + "\n"
    )

    live_handle.flush()


def run_scan(
    seeds: List[str],
    config: Config,
    live_path: Path,
    include_token: bool,
) -> Tuple[List[Finding], dict]:
    queue: Deque[Tuple[str, int]] = deque()
    queued: Set[str] = set()
    visited: Set[str] = set()
    seen_findings: Set[str] = set()

    findings: List[Finding] = []

    stats = {
        "seed_urls": len(seeds),
        "fetched": 0,
        "failed": 0,
        "discovered": 0,
        "virtual_sources": 0,
    }

    for seed in seeds:
        url = canonical_url(seed)

        if (
            url not in queued
            and host_in_scope(
                url,
                config.scope,
            )
        ):
            queue.append((url, 0))
            queued.add(url)

        elif not host_in_scope(
            url,
            config.scope,
        ):
            log(
                f"[scope] seed skipped: {url}"
            )

    live_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with live_path.open(
        "w",
        encoding="utf-8",
    ) as live_handle:
        if include_token:
            try:
                os.chmod(
                    live_path,
                    0o600,
                )
            except OSError:
                pass

        limit_label = (
            str(config.max_urls)
            if config.max_urls
            else "unlimited"
        )

        log(
            f"[start] {len(queue)} "
            "in-scope URL(s); "
            f"scope={','.join(config.scope)}; "
            f"threads={config.threads}; "
            f"max_urls={limit_label}; "
            f"live={live_path}"
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=config.threads
        ) as pool:
            pending: Dict[
                concurrent.futures.Future,
                Tuple[str, int],
            ] = {}

            while queue or pending:
                while (
                    queue
                    and len(pending) < config.threads
                    and (
                        config.max_urls == 0
                        or len(visited)
                        < config.max_urls
                    )
                ):
                    url, depth = queue.popleft()

                    if url in visited:
                        continue

                    visited.add(url)

                    log(
                        f"[fetch {len(visited)}/"
                        f"{limit_label}] "
                        f"depth={depth} {url}"
                    )

                    future = pool.submit(
                        fetch,
                        url,
                        config,
                    )

                    pending[future] = (
                        url,
                        depth,
                    )

                if not pending:
                    break

                done, _ = concurrent.futures.wait(
                    pending,
                    return_when=(
                        concurrent.futures.FIRST_COMPLETED
                    ),
                )

                for future in done:
                    requested_url, depth = pending.pop(
                        future
                    )

                    try:
                        result = future.result()

                    except Exception as error:
                        stats["failed"] += 1

                        log(
                            "[internal fetch error] "
                            f"{requested_url}: "
                            f"{type(error).__name__}"
                        )
                        continue

                    if result is None:
                        stats["failed"] += 1
                        continue

                    stats["fetched"] += 1
                    source = result.final_url

                    is_map = (
                        urlparse(source)
                        .path.lower()
                        .endswith(".map")
                    )

                    raw_transform = (
                        "source_map_raw"
                        if is_map
                        else "raw"
                    )

                    documents: List[
                        Tuple[str, str, str]
                    ] = [
                        (
                            source,
                            result.text,
                            raw_transform,
                        )
                    ]

                    documents.extend(
                        (
                            original,
                            content,
                            "sourcesContent",
                        )
                        for original, content in (
                            source_map_documents(
                                result.text,
                                source,
                            )
                        )
                    )

                    for (
                        label,
                        inline_map,
                    ) in inline_source_maps(
                        result.text,
                        source,
                    ):
                        documents.append(
                            (
                                label,
                                inline_map,
                                "inline_source_map",
                            )
                        )

                        documents.extend(
                            (
                                original,
                                content,
                                "sourcesContent",
                            )
                            for original, content in (
                                source_map_documents(
                                    inline_map,
                                    label,
                                )
                            )
                        )

                    for (
                        document_source,
                        content,
                        transform,
                    ) in documents:
                        if transform != "raw":
                            stats["virtual_sources"] += 1

                        document_findings = scan_text(
                            content,
                            document_source,
                            config,
                            transform,
                        )

                        for finding in document_findings:
                            if (
                                finding._token
                                in seen_findings
                            ):
                                continue

                            seen_findings.add(
                                finding._token
                            )

                            findings.append(finding)

                            emit_finding(
                                finding,
                                live_handle,
                                include_token,
                            )

                    if (
                        config.follow
                        and depth < config.max_depth
                    ):
                        newly_discovered = discover_urls(
                            result.text,
                            source,
                            config,
                        )

                        if is_map:
                            newly_discovered.update(
                                source_map_referenced_urls(
                                    result.text,
                                    source,
                                    config,
                                )
                            )

                        for discovered in newly_discovered:
                            if (
                                discovered in queued
                                or discovered in visited
                            ):
                                continue

                            if (
                                config.max_urls
                                and len(queued)
                                >= config.max_urls
                            ):
                                break

                            queue.append(
                                (
                                    discovered,
                                    depth + 1,
                                )
                            )

                            queued.add(discovered)
                            stats["discovered"] += 1

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            item.provider,
            item.source,
        )
    )

    stats["unique_findings"] = len(findings)
    stats["visited_urls"] = len(visited)

    return findings, stats


def write_reports(
    findings: List[Finding],
    output_prefix: Path,
    include_token: bool,
) -> Tuple[Path, Path]:
    output_prefix.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    json_path = Path(
        str(output_prefix) + ".json"
    )

    csv_path = Path(
        str(output_prefix) + ".csv"
    )

    with json_path.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            [
                finding.record(include_token)
                for finding in findings
            ],
            handle,
            indent=2,
            ensure_ascii=False,
        )

        handle.write("\n")

    fields = [
        "finding_id",
        "severity",
        "confidence",
        "provider",
        "category",
        "source",
        "line",
        "column",
        "transform",
        "redacted",
        "context",
    ]

    if include_token:
        fields.append("token")

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fields,
            extrasaction="ignore",
        )

        writer.writeheader()

        for finding in findings:
            writer.writerow(
                finding.record(include_token)
            )

    if include_token:
        for path in (
            json_path,
            csv_path,
        ):
            try:
                os.chmod(
                    path,
                    0o600,
                )
            except OSError:
                pass

    return json_path, csv_path


def looks_like_domain(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?=.{1,253}$)"
            r"(?:"
            r"[A-Za-z0-9]"
            r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"\."
            r")+"
            r"[A-Za-z]{2,63}",
            value,
        )
    )


def read_inputs(
    values: List[str],
) -> Tuple[List[str], List[Path]]:
    urls: List[str] = []
    files: List[Path] = []

    for value in values:
        candidate = Path(value).expanduser()

        if candidate.is_file():
            files.append(candidate.resolve())

            with candidate.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:
                for line_number, line in enumerate(
                    handle,
                    1,
                ):
                    item = line.strip()

                    if not item:
                        continue

                    if item.startswith("#"):
                        continue

                    parsed = urlparse(item)

                    try:
                        canonical = canonical_url(item)

                    except ValueError:
                        log(
                            "[input] ignored malformed URL "
                            f"{candidate}:{line_number}"
                        )
                        continue

                    if (
                        parsed.scheme
                        not in ("http", "https")
                        or not parsed.hostname
                    ):
                        log(
                            "[input] ignored malformed URL "
                            f"{candidate}:{line_number}"
                        )
                        continue

                    urls.append(canonical)

        else:
            parsed = urlparse(value)

            if (
                parsed.scheme in ("http", "https")
                and parsed.hostname
            ):
                urls.append(
                    canonical_url(value)
                )

            else:
                raise ValueError(
                    "input is neither an existing file "
                    "nor an HTTP(S) URL: "
                    f"{value}"
                )

    return list(dict.fromkeys(urls)), files


def infer_scopes(
    files: List[Path],
    urls: List[str],
) -> List[str]:
    inferred: List[str] = []

    for path in files:
        parent = (
            path.parent.name
            .lower()
            .rstrip(".")
        )

        if looks_like_domain(parent):
            inferred.append(parent)

    if not inferred:
        inferred.extend(
            (urlparse(url).hostname or "").lower()
            for url in urls
        )

    return list(
        dict.fromkeys(
            scope
            for scope in inferred
            if scope
        )
    )


def default_output_prefix(
    files: List[Path],
) -> Path:
    if files:
        parents = {
            path.parent
            for path in files
        }

        if len(parents) == 1:
            return (
                next(iter(parents))
                / "scan_results"
            )

    return Path.cwd() / "scan_results"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Scan recon.sh JavaScript URL lists "
            "for exposed API tokens."
        ),
        epilog=(
            "Example: python3 scan_ai_tokens.py "
            "output/example.com/js_urls.txt. "
            "Run only within written authorization."
        ),
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        help=(
            "Recon js_urls.txt files or "
            "direct HTTP(S) URLs."
        ),
    )

    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="DOMAIN",
        help=(
            "Authorized root domain; repeatable. "
            "Defaults to output/<domain>/."
        ),
    )

    parser.add_argument(
        "--out",
        metavar="PREFIX",
        help=(
            "Report prefix; defaults to "
            "<input-dir>/scan_results."
        ),
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Per-request timeout in seconds.",
    )

    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=(
            "Maximum bytes read or decoded "
            "per resource."
        ),
    )

    parser.add_argument(
        "--max-urls",
        type=int,
        default=DEFAULT_MAX_URLS,
        help=(
            "Maximum total seed and discovered URLs. "
            "Zero means unlimited and is the default."
        ),
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
        help=(
            "Maximum chunk and source-map "
            "discovery depth."
        ),
    )

    parser.add_argument(
        "--min-entropy",
        type=float,
        default=DEFAULT_MIN_ENTROPY,
    )

    parser.add_argument(
        "--no-follow",
        action="store_true",
        help=(
            "Do not follow in-scope chunks "
            "or source maps."
        ),
    )

    parser.add_argument(
        "--no-decode",
        action="store_true",
        help=(
            "Do not inspect Base64, escape, "
            "or concatenation transforms."
        ),
    )

    parser.add_argument(
        "--generic",
        action="store_true",
        help=(
            "Enable conservative generic api-key, "
            "secret, and token assignment detection. "
            "Off by default to prevent UI-name "
            "false positives."
        ),
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "Print progress and diagnostics. "
            "Off by default; normal output contains "
            "only [FOUND ...] lines."
        ),
    )

    parser.add_argument(
        "--full-tokens",
        action="store_true",
        help=(
            "Include full token values in report files. "
            "Files are permissioned 0600 when supported."
        ),
    )

    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "Exit 1 if findings exist. "
            "Default is 0 after a successful scan."
        ),
    )

    return parser


def validate_limits(
    args: argparse.Namespace,
) -> None:
    values = {
        "threads": (args.threads, 1),
        "timeout": (args.timeout, 1),
        "max-bytes": (args.max_bytes, 1),
        "max-urls": (args.max_urls, 0),
        "max-depth": (args.max_depth, 0),
    }

    for name, value_and_minimum in values.items():
        value, minimum = value_and_minimum

        if value < minimum:
            raise ValueError(
                f"--{name} must be at least {minimum}"
            )

    if not 0.0 <= args.min_entropy <= 1.0:
        raise ValueError(
            "--min-entropy must be between 0.0 and 1.0"
        )


def main(
    argv: Optional[List[str]] = None,
) -> int:
    global VERBOSE

    parser = build_parser()
    args = parser.parse_args(argv)

    VERBOSE = args.verbose

    try:
        validate_limits(args)

        seeds, input_files = read_inputs(
            args.inputs
        )

    except (
        OSError,
        ValueError,
    ) as error:
        parser.error(str(error))
        return 2

    if not seeds:
        parser.error(
            "no valid HTTP(S) URLs were found "
            "in the supplied input"
        )
        return 2

    explicit_scopes = [
        normalize_scope(value)
        for value in args.scope
    ]

    scopes = (
        [
            scope
            for scope in explicit_scopes
            if scope
        ]
        or infer_scopes(
            input_files,
            seeds,
        )
    )

    if not scopes:
        parser.error(
            "scope could not be inferred; "
            "pass --scope DOMAIN"
        )
        return 2

    bad_scopes = [
        scope
        for scope in scopes
        if not looks_like_domain(scope)
    ]

    if bad_scopes:
        parser.error(
            "invalid scope domain(s): "
            + ", ".join(bad_scopes)
        )
        return 2

    output_prefix = (
        Path(args.out).expanduser()
        if args.out
        else default_output_prefix(input_files)
    )

    output_prefix = output_prefix.resolve()

    live_path = Path(
        str(output_prefix) + ".live.jsonl"
    )

    config = Config(
        scope=list(dict.fromkeys(scopes)),
        threads=args.threads,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        max_urls=args.max_urls,
        max_depth=args.max_depth,
        min_entropy=args.min_entropy,
        follow=not args.no_follow,
        decode=not args.no_decode,
        generic=args.generic,
    )

    started = time.monotonic()

    findings, stats = run_scan(
        seeds,
        config,
        live_path,
        args.full_tokens,
    )

    elapsed = (
        time.monotonic()
        - started
    )

    json_path, csv_path = write_reports(
        findings,
        output_prefix,
        args.full_tokens,
    )

    log(
        f"[done] fetched={stats['fetched']} "
        f"failed={stats['failed']} "
        f"findings={len(findings)} "
        f"elapsed={elapsed:.1f}s"
    )

    log(f"[report] live: {live_path}")
    log(f"[report] json: {json_path}")
    log(f"[report] csv: {csv_path}")

    if args.full_tokens:
        log(
            "[warning] full token values were written; "
            "protect the reports as sensitive evidence."
        )

    if (
        args.fail_on_findings
        and findings
    ):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
