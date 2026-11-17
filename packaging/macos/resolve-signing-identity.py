#!/usr/bin/env python3
"""Resolve an unambiguous macOS code-signing identity, provisioning profiles, and timestamp policy."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shlex
import subprocess
import sys
import time
from typing import Any, Callable

APP_BUNDLE_ID = "com.clavis.app"
AGENT_BUNDLE_ID = "com.clavis.agent"
SHARED_KEYCHAIN_SUFFIX = "com.clavis.shared"
DEFAULT_REPO_PROFILE_DIR = Path(__file__).resolve().parent
DEFAULT_USER_PROFILE_DIRS = (
    Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles",
    Path.home() / "Library/MobileDevice/Provisioning Profiles",
)

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
SHA1_RE = re.compile(r"^[0-9A-Fa-f]{40}$")
IDENTITY_LINE_RE = re.compile(r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"]+)"\s*$')
CERT_BLOCK_RE = re.compile(
    r"SHA-1 hash:\s*([0-9A-Fa-f]{40})\s*\n(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
    re.DOTALL,
)
OU_RE = re.compile(r"(?:^|[,/])\s*OU=([A-Z0-9]{10})(?=\s*(?:[,/]|$))")
NOT_AFTER_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})(?:\s+(?:GMT|UTC))?$"
)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


class ResolutionError(Exception):
    """Raised when signing identity resolution fails closed."""


@dataclass(frozen=True)
class SigningIdentity:
    sha1: str
    cn: str
    team_id: str
    not_after_ts: float
    not_after: str


@dataclass(frozen=True)
class ProvisioningProfile:
    path: str
    uuid: str
    name: str
    app_id: str
    team_ids: tuple[str, ...]
    cert_sha1s: frozenset[str]
    keychain_access_groups: tuple[str, ...]
    platforms: tuple[str, ...]
    expires_ts: float
    expires_str: str
    provisions_all_devices: bool = False
    provisioned_devices: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ResolvedSigning:
    sign_arg: str
    sign_cn: str
    sign_team_id: str
    sign_label: str
    timestamp_flag: str
    designated_req: str = ""


@dataclass(frozen=True)
class ResolvedProvisioning:
    mode: str
    app_profile: str
    agent_profile: str
    keychain_access_group: str


def parse_openssl_not_after(value: str) -> float:
    """Parse OpenSSL `notAfter=` timestamp into UTC epoch seconds."""
    match = NOT_AFTER_RE.match(" ".join(value.strip().split()))
    if not match:
        return 0.0
    mon_str, day, hour, minute, second, year = match.groups()
    month = MONTHS.get(mon_str)
    if month is None:
        return 0.0
    return datetime(
        int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=timezone.utc
    ).timestamp()


def extract_team_id(subject: str) -> str:
    """Extract a 10-character Apple Team ID from an RFC2253 subject string."""
    match = OU_RE.search(subject)
    return match.group(1) if match else ""


def _inspect_pem(pem: str) -> tuple[str, float, str]:
    proc = subprocess.run(
        ["/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253", "-enddate"],
        input=pem,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return "", 0.0, ""
    team_id = ""
    not_after = ""
    not_after_ts = 0.0
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            team_id = extract_team_id(line.split("=", 1)[1].strip())
        elif line.startswith("notAfter="):
            not_after = " ".join(line.split("=", 1)[1].strip().split())
            not_after_ts = parse_openssl_not_after(not_after)
    return team_id, not_after_ts, not_after


def load_identities(keychain: str = "") -> list[SigningIdentity]:
    """Query valid codesigning identities and enrich them with X.509 metadata."""
    kc_args = [keychain] if keychain else []
    ident_proc = subprocess.run(
        ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning", *kc_args],
        text=True,
        capture_output=True,
        check=False,
    )
    if ident_proc.returncode != 0 and not ident_proc.stdout:
        return []

    cert_proc = subprocess.run(
        ["/usr/bin/security", "find-certificate", "-a", "-Z", "-p", *kc_args],
        text=True,
        capture_output=True,
        check=False,
    )
    cert_meta: dict[str, tuple[str, float, str]] = {}
    if cert_proc.returncode == 0 or cert_proc.stdout:
        for match in CERT_BLOCK_RE.finditer(cert_proc.stdout):
            sha1 = match.group(1).upper()
            if sha1 not in cert_meta:
                cert_meta[sha1] = _inspect_pem(match.group(2))

    identities: list[SigningIdentity] = []
    seen_sha1: set[str] = set()
    for line in ident_proc.stdout.splitlines():
        match = IDENTITY_LINE_RE.match(line)
        if not match:
            continue
        sha1 = match.group(1).upper()
        cn = match.group(2)
        if sha1 in seen_sha1:
            continue
        seen_sha1.add(sha1)
        team_id, not_after_ts, not_after = cert_meta.get(sha1, ("", 0.0, ""))
        identities.append(
            SigningIdentity(
                sha1=sha1,
                cn=cn,
                team_id=team_id,
                not_after_ts=not_after_ts,
                not_after=not_after,
            )
        )
    return identities


def _format_label(identity: SigningIdentity) -> str:
    short_sha = identity.sha1[:12]
    if identity.team_id:
        return f"{identity.cn} [team {identity.team_id}, {short_sha}]"
    return f"{identity.cn} [{short_sha}]"


def _format_available(identities: list[SigningIdentity]) -> str:
    if not identities:
        return "  (none)"
    lines = []
    for item in identities:
        team = item.team_id or "-"
        expiry = item.not_after or "unknown"
        lines.append(f"  - {item.sha1}  {item.cn}  (team: {team}, expires: {expiry})")
    return "\n".join(lines)


def _pick_best(candidates: list[SigningIdentity], preferred_team_id: str) -> SigningIdentity:
    pool = candidates
    if preferred_team_id:
        preferred = [c for c in pool if c.team_id == preferred_team_id]
        if preferred:
            pool = preferred
    # Python sort is stable, so ties preserve keychain discovery order.
    ranked = sorted(pool, key=lambda c: c.not_after_ts, reverse=True)
    return ranked[0]


def compute_designated_req(sign_arg: str, sign_cn: str, sign_team_id: str) -> str:
    """Return the team-anchored designated requirement for Apple-rooted identities."""
    if (
        sign_arg != "-"
        and sign_team_id
        and (
            sign_cn.startswith("Apple Development")
            or sign_cn.startswith("Developer ID Application")
        )
    ):
        return (
            '=designated => identifier "Clavis" and anchor apple generic and '
            '(certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */ or '
            'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */) and '
            f'certificate leaf[subject.OU] = "{sign_team_id}"'
        )
    return ""


def is_macos_platform(platforms: tuple[str, ...]) -> bool:
    """Return True strictly when macOS/OSX is present in the profile Platform list."""
    lowered = {p.lower() for p in platforms if p}
    return bool(lowered & {"macos", "osx"})


def _normalize_str_tuple(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        return (raw,) if raw else ()
    if isinstance(raw, (list, tuple)):
        return tuple(str(item) for item in raw if item)
    return ()


def parse_provisioning_plist(data: dict[str, Any], path: str = "") -> ProvisioningProfile:
    """Extract normalized metadata and entitlements from a decoded provisioning plist."""
    if not isinstance(data, dict):
        raise ResolutionError(f"❌ Provisioning profile '{path or '<plist>'}' did not decode to a dictionary.")

    raw_certs = data.get("DeveloperCertificates")
    cert_sha1s: set[str] = set()
    if isinstance(raw_certs, (list, tuple)):
        for cert in raw_certs:
            if isinstance(cert, (bytes, bytearray)):
                cert_sha1s.add(hashlib.sha1(bytes(cert)).hexdigest().upper())

    team_ids = _normalize_str_tuple(data.get("TeamIdentifier"))
    platforms = _normalize_str_tuple(data.get("Platform"))

    exp = data.get("ExpirationDate")
    if isinstance(exp, datetime):
        exp_utc = exp.replace(tzinfo=timezone.utc) if exp.tzinfo is None else exp.astimezone(timezone.utc)
        expires_ts = exp_utc.timestamp()
        expires_str = exp_utc.strftime("%Y-%m-%d %H:%M:%SZ")
    else:
        expires_ts = 0.0
        expires_str = "unknown"

    entitlements = data.get("Entitlements")
    if not isinstance(entitlements, dict):
        entitlements = {}

    app_id = str(
        entitlements.get("com.apple.application-identifier")
        or entitlements.get("application-identifier")
        or ""
    )
    keychain_access_groups = _normalize_str_tuple(entitlements.get("keychain-access-groups"))
    provisions_all_devices = bool(data.get("ProvisionsAllDevices"))
    provisioned_devices = frozenset(_normalize_str_tuple(data.get("ProvisionedDevices")))

    # If UIDeviceFamily is present without a macOS/OSX platform, platforms stays non-macOS and fails matching.
    return ProvisioningProfile(
        path=path,
        uuid=str(data.get("UUID") or ""),
        name=str(data.get("Name") or ""),
        app_id=app_id,
        team_ids=team_ids,
        cert_sha1s=frozenset(cert_sha1s),
        keychain_access_groups=keychain_access_groups,
        platforms=platforms,
        expires_ts=expires_ts,
        expires_str=expires_str,
        provisions_all_devices=provisions_all_devices,
        provisioned_devices=provisioned_devices,
    )


def load_provisioning_profile(path: str, *, explicit: bool = False) -> ProvisioningProfile:
    """Decode and parse a .provisionprofile using `/usr/bin/security cms -D -i`."""
    expanded = os.path.expanduser(path)
    if expanded.lower().endswith(".mobileprovision") and not explicit:
        raise ResolutionError(f"❌ Refusing iOS '.mobileprovision' profile during macOS auto-discovery: '{expanded}'.")
    if not os.path.isfile(expanded):
        raise ResolutionError(f"❌ Provisioning profile not found: '{expanded}'.")

    proc = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i", expanded],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        detail = proc.stderr.decode("utf-8", errors="replace").strip() if proc.stderr else "invalid CMS envelope"
        raise ResolutionError(f"❌ Failed to decode provisioning profile '{expanded}': {detail}")

    try:
        plist_data = plistlib.loads(proc.stdout)
    except Exception as exc:
        raise ResolutionError(f"❌ Failed to parse plist inside provisioning profile '{expanded}': {exc}") from exc

    return parse_provisioning_plist(plist_data, path=expanded)


def _keychain_group_matches(groups: tuple[str, ...], *, team_id: str, shared_group: str) -> bool:
    if shared_group in groups:
        return True
    # Apple Developer Portal macOS profiles commonly issue `<TEAM_ID>.*` as the keychain-access-groups allowlist.
    if team_id and shared_group.startswith(f"{team_id}.") and f"{team_id}.*" in groups:
        return True
    return False


def _app_id_matches(profile_app_id: str, *, team_id: str, bundle_id: str) -> bool:
    if not team_id:
        return False
    return profile_app_id == f"{team_id}.{bundle_id}" or profile_app_id == f"{team_id}.*"


def detect_local_provisioning_udid() -> str:
    """Return this Mac's Provisioning UDID via `system_profiler SPHardwareDataType`, or empty string."""
    proc = subprocess.run(
        ["/usr/sbin/system_profiler", "SPHardwareDataType"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return ""
    match = re.search(r"Provisioning UDID:\s*(\S+)", proc.stdout)
    return match.group(1).strip() if match else ""


def _device_udid_matches(profile: ProvisioningProfile, local_udid: str) -> bool:
    if not local_udid or profile.provisions_all_devices or not profile.provisioned_devices:
        return True
    return local_udid in profile.provisioned_devices


def profile_mismatch_reasons(
    profile: ProvisioningProfile,
    *,
    bundle_id: str,
    team_id: str,
    cert_sha1: str,
    shared_group: str,
    now_ts: float,
    local_udid: str = "",
) -> list[str]:
    """Return human-readable reasons why `profile` does not match, or empty list if valid."""
    reasons: list[str] = []
    if not is_macos_platform(profile.platforms):
        found = list(profile.platforms) if profile.platforms else ["(missing)"]
        reasons.append(f"platform {found} is not macOS")
    if not team_id or team_id not in profile.team_ids:
        reasons.append(f"TeamIdentifier {list(profile.team_ids) or ['(none)']} does not include '{team_id}'")
    if not cert_sha1 or cert_sha1.upper() not in profile.cert_sha1s:
        reasons.append(f"signing cert SHA-1 '{cert_sha1.upper()}' is not in DeveloperCertificates")
    expected_app_id = f"{team_id}.{bundle_id}" if team_id else bundle_id
    if not _app_id_matches(profile.app_id, team_id=team_id, bundle_id=bundle_id):
        reasons.append(f"com.apple.application-identifier '{profile.app_id or '(missing)'}' != '{expected_app_id}'")
    if not _keychain_group_matches(profile.keychain_access_groups, team_id=team_id, shared_group=shared_group):
        reasons.append(
            f"keychain-access-groups {list(profile.keychain_access_groups)} does not cover '{shared_group}'"
        )
    if profile.expires_ts <= now_ts:
        reasons.append(f"expired at {profile.expires_str}")
    if not _device_udid_matches(profile, local_udid):
        reasons.append(f"host UDID '{local_udid}' is not in ProvisionedDevices")
    return reasons


def profile_matches(
    profile: ProvisioningProfile,
    *,
    bundle_id: str,
    team_id: str,
    cert_sha1: str,
    shared_group: str,
    now_ts: float | None = None,
    local_udid: str = "",
) -> bool:
    """Return True if `profile` satisfies macOS platform, team, cert, app ID, shared keychain, UDID, and expiry checks."""
    check_ts = time.time() if now_ts is None else now_ts
    return (
        bool(team_id)
        and team_id in profile.team_ids
        and bool(cert_sha1)
        and cert_sha1.upper() in profile.cert_sha1s
        and _app_id_matches(profile.app_id, team_id=team_id, bundle_id=bundle_id)
        and _keychain_group_matches(profile.keychain_access_groups, team_id=team_id, shared_group=shared_group)
        and profile.expires_ts > check_ts
        and is_macos_platform(profile.platforms)
        and _device_udid_matches(profile, local_udid)
    )


def discover_provisioning_profiles(
    *,
    repo_dir: Path | None = None,
    user_dirs: tuple[Path, ...] | list[Path] | None = None,
) -> list[ProvisioningProfile]:
    """Discover and parse `.provisionprofile` files from repo-local and Xcode/MobileDevice directories."""
    repo_base = DEFAULT_REPO_PROFILE_DIR if repo_dir is None else repo_dir
    search_dirs = DEFAULT_USER_PROFILE_DIRS if user_dirs is None else tuple(user_dirs)

    candidates: list[Path] = [
        repo_base / "Clavis.provisionprofile",
        repo_base / "ClavisAgent.provisionprofile",
    ]
    for directory in search_dirs:
        if directory.is_dir():
            candidates.extend(sorted(directory.glob("*.provisionprofile")))

    profiles: list[ProvisioningProfile] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.is_file():
            continue
        real = os.path.realpath(candidate)
        if real in seen:
            continue
        seen.add(real)
        try:
            profiles.append(load_provisioning_profile(str(candidate), explicit=False))
        except ResolutionError:
            # Skip unreadable/non-macOS stray files during auto-discovery; explicit paths still fail closed.
            continue
    return profiles


def resolve_provisioning(
    resolved: ResolvedSigning,
    *,
    app_profile: str = "",
    agent_profile: str = "",
    require_provisioning: bool = False,
    discovered_profiles: list[ProvisioningProfile] | None = None,
    profile_loader: Callable[[str], ProvisioningProfile] | None = None,
    now_ts: float | None = None,
    local_udid: str | None = None,
) -> ResolvedProvisioning:
    """Resolve atomic (Clavis.app + Clavis Agent.app) Data Protection provisioning profiles."""
    check_ts = time.time() if now_ts is None else now_ts
    app_arg = app_profile.strip()
    agent_arg = agent_profile.strip()
    has_explicit_pair = bool(app_arg or agent_arg)

    if has_explicit_pair and (not app_arg or not agent_arg):
        raise ResolutionError(
            "❌ Both --app-profile and --agent-profile must be provided together (atomic Data Protection pair)."
        )

    if resolved.sign_arg == "-" or not resolved.sign_team_id:
        if has_explicit_pair:
            raise ResolutionError(
                "❌ Explicit provisioning profiles require a real signing certificate with a Team ID (cannot use ad-hoc '-')."
            )
        if require_provisioning:
            raise ResolutionError(
                "❌ CLAVIS_REQUIRE_PROVISIONING=1 requires a real signing identity with a Team ID and matching provisioning profiles."
            )
        return ResolvedProvisioning(
            mode="unprovisioned",
            app_profile="",
            agent_profile="",
            keychain_access_group="",
        )

    team_id = resolved.sign_team_id
    cert_sha1 = resolved.sign_arg
    shared_group = f"{team_id}.{SHARED_KEYCHAIN_SUFFIX}"
    loader = profile_loader or (lambda path: load_provisioning_profile(path, explicit=True))

    if has_explicit_pair:
        effective_udid = "" if local_udid is None else local_udid
        loaded_app = loader(app_arg)
        loaded_agent = loader(agent_arg)
        app_reasons = profile_mismatch_reasons(
            loaded_app,
            bundle_id=APP_BUNDLE_ID,
            team_id=team_id,
            cert_sha1=cert_sha1,
            shared_group=shared_group,
            now_ts=check_ts,
            local_udid=effective_udid,
        )
        if app_reasons:
            raise ResolutionError(
                f"❌ App provisioning profile '{loaded_app.path}' is invalid for {APP_BUNDLE_ID}: {'; '.join(app_reasons)}."
            )
        agent_reasons = profile_mismatch_reasons(
            loaded_agent,
            bundle_id=AGENT_BUNDLE_ID,
            team_id=team_id,
            cert_sha1=cert_sha1,
            shared_group=shared_group,
            now_ts=check_ts,
            local_udid=effective_udid,
        )
        if agent_reasons:
            raise ResolutionError(
                f"❌ Agent provisioning profile '{loaded_agent.path}' is invalid for {AGENT_BUNDLE_ID}: {'; '.join(agent_reasons)}."
            )
        return ResolvedProvisioning(
            mode="data-protection",
            app_profile=loaded_app.path,
            agent_profile=loaded_agent.path,
            keychain_access_group=shared_group,
        )

    if local_udid is not None:
        effective_udid = local_udid
    elif discovered_profiles is None:
        effective_udid = detect_local_provisioning_udid()
    else:
        effective_udid = ""

    profiles = discover_provisioning_profiles() if discovered_profiles is None else discovered_profiles
    app_matches = [
        p
        for p in profiles
        if profile_matches(
            p,
            bundle_id=APP_BUNDLE_ID,
            team_id=team_id,
            cert_sha1=cert_sha1,
            shared_group=shared_group,
            now_ts=check_ts,
            local_udid=effective_udid,
        )
    ]
    agent_matches = [
        p
        for p in profiles
        if profile_matches(
            p,
            bundle_id=AGENT_BUNDLE_ID,
            team_id=team_id,
            cert_sha1=cert_sha1,
            shared_group=shared_group,
            now_ts=check_ts,
            local_udid=effective_udid,
        )
    ]

    if app_matches and agent_matches:
        best_app = sorted(
            app_matches,
            key=lambda p: (p.app_id == f"{team_id}.{APP_BUNDLE_ID}", p.expires_ts),
            reverse=True,
        )[0]
        best_agent = sorted(
            agent_matches,
            key=lambda p: (p.app_id == f"{team_id}.{AGENT_BUNDLE_ID}", p.expires_ts),
            reverse=True,
        )[0]
        return ResolvedProvisioning(
            mode="data-protection",
            app_profile=best_app.path,
            agent_profile=best_agent.path,
            keychain_access_group=shared_group,
        )

    if require_provisioning:
        missing_bundles: list[str] = []
        if not app_matches:
            missing_bundles.append(APP_BUNDLE_ID)
        if not agent_matches:
            missing_bundles.append(AGENT_BUNDLE_ID)
        raise ResolutionError(
            "❌ CLAVIS_REQUIRE_PROVISIONING=1 failed: missing or invalid macOS provisioning profile(s) for "
            f"{', '.join(missing_bundles)} (team={team_id}, cert={cert_sha1}, group={shared_group})."
        )

    return ResolvedProvisioning(
        mode="unprovisioned",
        app_profile="",
        agent_profile="",
        keychain_access_group="",
    )


def select_identity(
    identities: list[SigningIdentity],
    *,
    requested: str = "",
    preferred_team_id: str = "4G6X3KNZUS",
    expected_team_id: str = "",
    notarize: bool = False,
    allow_adhoc: bool = False,
    timestamp_mode: str = "auto",
) -> ResolvedSigning:
    """Resolve an unambiguous signing identity and timestamp flag."""
    if timestamp_mode not in {"auto", "secure", "none"}:
        raise ResolutionError("❌ CLAVIS_TIMESTAMP must be auto, secure or none.")
    if expected_team_id and not TEAM_ID_RE.fullmatch(expected_team_id):
        raise ResolutionError(
            f"❌ CLAVIS_EXPECTED_TEAM_ID must be a 10-character alphanumeric Team ID, got '{expected_team_id}'."
        )
    if preferred_team_id and not TEAM_ID_RE.fullmatch(preferred_team_id):
        raise ResolutionError(
            f"❌ CLAVIS_TEAM_ID must be a 10-character alphanumeric Team ID, got '{preferred_team_id}'."
        )

    if requested == "-":
        if notarize:
            raise ResolutionError("❌ Notarization requires a 'Developer ID Application' identity, got '-'.")
        if expected_team_id:
            raise ResolutionError(
                f"❌ Ad-hoc identity '-' cannot satisfy CLAVIS_EXPECTED_TEAM_ID '{expected_team_id}'."
            )
        ts_flag = "--timestamp" if timestamp_mode == "secure" else "--timestamp=none"
        return ResolvedSigning(
            sign_arg="-",
            sign_cn="-",
            sign_team_id="",
            sign_label="- (ad-hoc)",
            timestamp_flag=ts_flag,
        )

    chosen: SigningIdentity | None = None
    if requested:
        req_upper = requested.upper()
        is_sha1 = bool(SHA1_RE.fullmatch(req_upper))
        matched = [
            c
            for c in identities
            if (is_sha1 and c.sha1 == req_upper) or c.cn == requested or c.cn.startswith(requested)
        ]
        if not matched:
            raise ResolutionError(
                f"❌ Signing identity '{requested}' not found in keychain.\n"
                f"Available valid identities:\n{_format_available(identities)}"
            )
        if expected_team_id:
            team_matched = [c for c in matched if c.team_id == expected_team_id]
            if not team_matched:
                found_teams = ", ".join(sorted({c.team_id or "(none)" for c in matched}))
                raise ResolutionError(
                    f"❌ Signing identity '{requested}' belongs to team(s) [{found_teams}], "
                    f"expected '{expected_team_id}'."
                )
            matched = team_matched
        chosen = _pick_best(matched, preferred_team_id)
    else:
        pool = [c for c in identities if c.team_id == expected_team_id] if expected_team_id else list(identities)
        if notarize:
            dev_id = [c for c in pool if c.cn.startswith("Developer ID Application")]
            if not dev_id:
                team_note = f" for team '{expected_team_id}'" if expected_team_id else ""
                raise ResolutionError(
                    f"❌ CLAVIS_NOTARIZE=1 requires a 'Developer ID Application' certificate{team_note}.\n"
                    f"Available valid identities:\n{_format_available(identities)}"
                )
            chosen = _pick_best(dev_id, preferred_team_id)
        else:
            tiers = [
                [c for c in pool if c.cn.startswith("Apple Development")],
                [c for c in pool if c.cn.startswith("Developer ID Application")],
            ]
            if not expected_team_id:
                tiers.append([c for c in pool if c.cn == "Clavis Local Development"])
            for tier in tiers:
                if tier:
                    chosen = _pick_best(tier, preferred_team_id)
                    break

            if chosen is None:
                if allow_adhoc and not expected_team_id:
                    ts_flag = "--timestamp" if timestamp_mode == "secure" else "--timestamp=none"
                    return ResolvedSigning(
                        sign_arg="-",
                        sign_cn="-",
                        sign_team_id="",
                        sign_label="- (ad-hoc)",
                        timestamp_flag=ts_flag,
                    )
                if expected_team_id:
                    raise ResolutionError(
                        f"❌ No code-signing certificate found for team '{expected_team_id}'.\n"
                        f"Available valid identities:\n{_format_available(identities)}"
                    )
                raise ResolutionError(
                    "❌ No code-signing certificate found; refusing to create an unsigned/ad-hoc build.\n"
                    "   Install a signing certificate, set CLAVIS_SIGN_IDENTITY, or pass CLAVIS_ALLOW_ADHOC_SIGNING=1."
                )

    is_dev_id = chosen.cn.startswith("Developer ID Application")
    if notarize and not is_dev_id:
        raise ResolutionError(
            f"❌ Notarization requires a 'Developer ID Application' identity, got '{chosen.cn}'."
        )

    if timestamp_mode == "secure":
        ts_flag = "--timestamp"
    elif timestamp_mode == "none":
        ts_flag = "--timestamp=none"
    else:
        ts_flag = "--timestamp" if is_dev_id else "--timestamp=none"

    if notarize and ts_flag != "--timestamp":
        raise ResolutionError(
            "❌ Notarization requires secure timestamps (CLAVIS_TIMESTAMP must be auto or secure)."
        )

    return ResolvedSigning(
        sign_arg=chosen.sha1,
        sign_cn=chosen.cn,
        sign_team_id=chosen.team_id,
        sign_label=_format_label(chosen),
        timestamp_flag=ts_flag,
        designated_req=compute_designated_req(chosen.sha1, chosen.cn, chosen.team_id),
    )


def print_status(
    identities: list[SigningIdentity],
    *,
    keychain: str,
    requested: str,
    preferred_team_id: str,
    expected_team_id: str,
    notarize: bool,
    allow_adhoc: bool,
    timestamp_mode: str,
    app_profile: str = "",
    agent_profile: str = "",
    require_provisioning: bool = False,
) -> int:
    """Print keychain signing and Data Protection provisioning diagnostics; return 0 on success or 1 on failure."""
    scope = keychain or "default search list (login + system)"
    target_team = expected_team_id or preferred_team_id
    print(f"Keychain scope:     {scope}")
    print(f"Preferred Team ID:  {preferred_team_id or '(none)'}")
    if expected_team_id:
        print(f"Expected Team ID:   {expected_team_id}")
    print("\nValid code-signing identities:")
    print(_format_available(identities))

    dev_id_matches = [
        c
        for c in identities
        if c.cn.startswith("Developer ID Application") and (not target_team or c.team_id == target_team)
    ]
    print()
    if dev_id_matches:
        best_dev_id = _pick_best(dev_id_matches, preferred_team_id)
        print(f"Developer ID ready: yes ({_format_label(best_dev_id)}, expires: {best_dev_id.not_after or 'unknown'})")
    else:
        print(f"Developer ID ready: no (no 'Developer ID Application' certificate for team '{target_team or 'any'}')")

    try:
        resolved = select_identity(
            identities,
            requested=requested,
            preferred_team_id=preferred_team_id,
            expected_team_id=expected_team_id,
            notarize=notarize,
            allow_adhoc=allow_adhoc,
            timestamp_mode=timestamp_mode,
        )
        print(f"Active selection:   {resolved.sign_label} ({resolved.timestamp_flag})")
        print(f"codesign --sign:    {resolved.sign_arg}")
        print(f"Designated req:     {resolved.designated_req or '(default / none)'}")

        provisioning = resolve_provisioning(
            resolved,
            app_profile=app_profile,
            agent_profile=agent_profile,
            require_provisioning=require_provisioning,
        )
        if provisioning.mode == "data-protection":
            print(f"Data Protection:    enabled ({provisioning.mode}, group: {provisioning.keychain_access_group})")
            print(f"  App profile:      {provisioning.app_profile}")
            print(f"  Agent profile:    {provisioning.agent_profile}")
        else:
            reason = "ad-hoc / no Team ID" if (resolved.sign_arg == "-" or not resolved.sign_team_id) else "atomic pair not found"
            print(f"Data Protection:    {provisioning.mode} ({reason}; legacy keychain fallback)")
        return 0
    except ResolutionError as err:
        print(f"\n{err}", file=sys.stderr)
        return 1


def run_self_test() -> None:
    """Run unit tests for identity selection rules without touching Keychain."""
    personal_dev = SigningIdentity(
        sha1="771653AEC748C9C346DA95907CD0569F45687394",
        cn="Apple Development: gosugdr@gmail.com (8WWS3VX6GG)",
        team_id="P7P693LH69",
        not_after_ts=1821437860.0,
        not_after="Sep 20 10:57:40 2027 GMT",
    )
    paid_dev = SigningIdentity(
        sha1="7C2912E7F5954B7452DB1D994B5527433921D1BA",
        cn="Apple Development: nullgdr@gmail.com (69XMYRYRQ2)",
        team_id="4G6X3KNZUS",
        not_after_ts=1825677916.0,
        not_after="Nov 8 12:45:16 2027 GMT",
    )
    dev_id_older = SigningIdentity(
        sha1="1111111111111111111111111111111111111111",
        cn="Developer ID Application: Damir Garifullin (4G6X3KNZUS)",
        team_id="4G6X3KNZUS",
        not_after_ts=1800000000.0,
        not_after="Jan 15 08:00:00 2027 GMT",
    )
    dev_id_newer = SigningIdentity(
        sha1="2222222222222222222222222222222222222222",
        cn="Developer ID Application: Damir Garifullin (4G6X3KNZUS)",
        team_id="4G6X3KNZUS",
        not_after_ts=1900000000.0,
        not_after="Mar 18 00:26:40 2030 GMT",
    )
    contributor_dev = SigningIdentity(
        sha1="3333333333333333333333333333333333333333",
        cn="Apple Development: contributor@example.com (ABCD123456)",
        team_id="XYZ9876543",
        not_after_ts=1820000000.0,
        not_after="Sep 3 17:46:40 2027 GMT",
    )

    # 1. Ambiguous Apple Development across P7P693LH69 and 4G6X3KNZUS selects 4G6X3KNZUS SHA-1.
    r1 = select_identity([personal_dev, paid_dev], preferred_team_id="4G6X3KNZUS")
    assert r1.sign_arg == paid_dev.sha1, f"expected {paid_dev.sha1}, got {r1.sign_arg}"
    assert r1.sign_team_id == "4G6X3KNZUS"
    assert r1.timestamp_flag == "--timestamp=none"

    # 2. Explicit prefix "Developer ID Application" with two certs selects latest expiry SHA-1.
    r2 = select_identity(
        [dev_id_older, dev_id_newer],
        requested="Developer ID Application",
        preferred_team_id="4G6X3KNZUS",
        notarize=True,
    )
    assert r2.sign_arg == dev_id_newer.sha1, f"expected {dev_id_newer.sha1}, got {r2.sign_arg}"
    assert r2.timestamp_flag == "--timestamp"

    # 3. Expected team ID mismatch rejects personal cert.
    try:
        select_identity([personal_dev], expected_team_id="4G6X3KNZUS")
        raise AssertionError("expected ResolutionError for team mismatch")
    except ResolutionError:
        pass

    # 4. Single contributor cert on another team with empty expected_team_id falls back cleanly.
    r4 = select_identity([contributor_dev], preferred_team_id="4G6X3KNZUS", expected_team_id="")
    assert r4.sign_arg == contributor_dev.sha1
    assert r4.sign_team_id == "XYZ9876543"

    # 5. Notarization rejects Apple Development-only keychains.
    try:
        select_identity([paid_dev], preferred_team_id="4G6X3KNZUS", notarize=True)
        raise AssertionError("expected ResolutionError for notarize without Developer ID")
    except ResolutionError:
        pass

    # 6. Empty certs + allow_adhoc=True resolves to ad-hoc "-".
    r6 = select_identity([], preferred_team_id="4G6X3KNZUS", allow_adhoc=True)
    assert r6.sign_arg == "-"
    assert r6.sign_team_id == ""
    assert r6.timestamp_flag == "--timestamp=none"

    # 7. OpenSSL expiry parsing & Team ID extraction sanity checks.
    assert extract_team_id("C=US,O=Damir Garifullin,OU=4G6X3KNZUS,CN=Apple Development: nullgdr@gmail.com") == "4G6X3KNZUS"
    assert extract_team_id("CN=Apple Worldwide Developer Relations,OU=G3,O=Apple Inc.") == ""
    assert parse_openssl_not_after("Nov  8 12:45:16 2027 GMT") > parse_openssl_not_after("Sep 20 10:57:40 2027 GMT")

    # 8. DESIGNATED_REQ exact values for Apple Development, Developer ID, local custom, and ad-hoc.
    expected_req = (
        '=designated => identifier "Clavis" and anchor apple generic and '
        '(certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */ or '
        'certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */) and '
        'certificate leaf[subject.OU] = "4G6X3KNZUS"'
    )
    assert r1.designated_req == expected_req, f"unexpected Apple Development DESIGNATED_REQ: {r1.designated_req!r}"
    assert r2.designated_req == expected_req, f"unexpected Developer ID DESIGNATED_REQ: {r2.designated_req!r}"
    assert r6.designated_req == "", f"expected empty DESIGNATED_REQ for ad-hoc, got {r6.designated_req!r}"
    local_custom = SigningIdentity(
        sha1="4444444444444444444444444444444444444444",
        cn="Clavis Local Development",
        team_id="",
        not_after_ts=1900000000.0,
        not_after="Mar 18 00:26:40 2030 GMT",
    )
    r_local = select_identity([local_custom], preferred_team_id="4G6X3KNZUS")
    assert r_local.designated_req == "", f"expected empty DESIGNATED_REQ for custom local cert, got {r_local.designated_req!r}"

    # 9. Provisioning plist parsing & UTC ExpirationDate handling.
    now_ts = 1800000000.0
    future_dt = datetime(2028, 6, 1, 12, 0, 0)  # naive UTC as returned by plistlib.loads
    past_dt = datetime(2025, 1, 1, 0, 0, 0)
    fake_cert_der = b"fake-developer-id-der-cert"
    fake_cert_sha1 = hashlib.sha1(fake_cert_der).hexdigest().upper()
    assert fake_cert_sha1 != dev_id_newer.sha1

    parsed_mac = parse_provisioning_plist(
        {
            "UUID": "uuid-app-1",
            "Name": "Clavis macOS App",
            "TeamIdentifier": ["4G6X3KNZUS"],
            "Platform": "OSX",
            "ExpirationDate": future_dt,
            "DeveloperCertificates": [fake_cert_der],
            "Entitlements": {
                "com.apple.application-identifier": "4G6X3KNZUS.com.clavis.app",
                "keychain-access-groups": ["4G6X3KNZUS.com.clavis.shared"],
            },
        },
        path="/tmp/Clavis.provisionprofile",
    )
    assert parsed_mac.platforms == ("OSX",)
    assert fake_cert_sha1 in parsed_mac.cert_sha1s
    assert parsed_mac.expires_ts == future_dt.replace(tzinfo=timezone.utc).timestamp()

    parsed_ios = parse_provisioning_plist(
        {
            "UUID": "uuid-ios-1",
            "Name": "iOS Team Provisioning Profile: *",
            "TeamIdentifier": ["4G6X3KNZUS"],
            "Platform": ["iOS", "xrOS", "visionOS"],
            "UIDeviceFamily": [1, 2],
            "ExpirationDate": future_dt,
            "DeveloperCertificates": [fake_cert_der],
            "Entitlements": {
                "com.apple.application-identifier": "4G6X3KNZUS.com.clavis.app",
                "keychain-access-groups": ["4G6X3KNZUS.com.clavis.shared"],
            },
        },
        path="/tmp/ios.mobileprovision",
    )
    assert not profile_matches(
        parsed_ios,
        bundle_id=APP_BUNDLE_ID,
        team_id="4G6X3KNZUS",
        cert_sha1=fake_cert_sha1,
        shared_group="4G6X3KNZUS.com.clavis.shared",
        now_ts=now_ts,
    ), "iOS profile must be rejected"

    # Profile with UIDeviceFamily and missing Platform must also be rejected.
    parsed_no_platform = parse_provisioning_plist(
        {
            "UUID": "uuid-no-plat",
            "Name": "Missing Platform",
            "TeamIdentifier": ["4G6X3KNZUS"],
            "UIDeviceFamily": [1],
            "ExpirationDate": future_dt,
            "DeveloperCertificates": [fake_cert_der],
            "Entitlements": {
                "com.apple.application-identifier": "4G6X3KNZUS.com.clavis.app",
                "keychain-access-groups": ["4G6X3KNZUS.com.clavis.shared"],
            },
        },
        path="/tmp/noplat.provisionprofile",
    )
    assert not profile_matches(
        parsed_no_platform,
        bundle_id=APP_BUNDLE_ID,
        team_id="4G6X3KNZUS",
        cert_sha1=fake_cert_sha1,
        shared_group="4G6X3KNZUS.com.clavis.shared",
        now_ts=now_ts,
    )

    # 10. Cert SHA-1 mismatch, expired profile, wrong keychain group, and wildcard group checks.
    app_older = ProvisioningProfile(
        path="/tmp/Clavis-older.provisionprofile",
        uuid="u-app-old",
        name="Clavis App Old",
        app_id="4G6X3KNZUS.com.clavis.app",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({dev_id_newer.sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("macOS",),
        expires_ts=now_ts + 1000.0,
        expires_str="2027-01-15 08:16:40Z",
    )
    app_newer = ProvisioningProfile(
        path="/tmp/Clavis-newer.provisionprofile",
        uuid="u-app-new",
        name="Clavis App New",
        app_id="4G6X3KNZUS.com.clavis.app",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({dev_id_newer.sha1}),
        keychain_access_groups=("4G6X3KNZUS.*",),
        platforms=("OSX",),
        expires_ts=now_ts + 5000.0,
        expires_str="2027-01-15 09:23:20Z",
    )
    agent_valid = ProvisioningProfile(
        path="/tmp/ClavisAgent.provisionprofile",
        uuid="u-agent",
        name="Clavis Agent",
        app_id="4G6X3KNZUS.com.clavis.agent",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({dev_id_newer.sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("macOS",),
        expires_ts=now_ts + 2000.0,
        expires_str="2027-01-15 08:33:20Z",
    )
    agent_expired = ProvisioningProfile(
        path="/tmp/ClavisAgent-expired.provisionprofile",
        uuid="u-agent-exp",
        name="Clavis Agent Expired",
        app_id="4G6X3KNZUS.com.clavis.agent",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({dev_id_newer.sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("macOS",),
        expires_ts=past_dt.replace(tzinfo=timezone.utc).timestamp(),
        expires_str="2025-01-01 00:00:00Z",
    )
    agent_wrong_cert = ProvisioningProfile(
        path="/tmp/ClavisAgent-wrongcert.provisionprofile",
        uuid="u-agent-cert",
        name="Clavis Agent Wrong Cert",
        app_id="4G6X3KNZUS.com.clavis.agent",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({dev_id_older.sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("macOS",),
        expires_ts=now_ts + 2000.0,
        expires_str="2027-01-15 08:33:20Z",
    )

    assert not profile_matches(
        agent_wrong_cert,
        bundle_id=AGENT_BUNDLE_ID,
        team_id="4G6X3KNZUS",
        cert_sha1=dev_id_newer.sha1,
        shared_group="4G6X3KNZUS.com.clavis.shared",
        now_ts=now_ts,
    ), "cert SHA-1 mismatch must be rejected"
    assert not profile_matches(
        agent_expired,
        bundle_id=AGENT_BUNDLE_ID,
        team_id="4G6X3KNZUS",
        cert_sha1=dev_id_newer.sha1,
        shared_group="4G6X3KNZUS.com.clavis.shared",
        now_ts=now_ts,
    ), "expired profile must be rejected"

    # 11. Atomic pair auto-discovery picks latest valid pair -> data-protection.
    prov_ok = resolve_provisioning(
        r2,
        discovered_profiles=[parsed_ios, app_older, app_newer, agent_expired, agent_valid],
        now_ts=now_ts,
    )
    assert prov_ok.mode == "data-protection"
    assert prov_ok.app_profile == app_newer.path
    assert prov_ok.agent_profile == agent_valid.path
    assert prov_ok.keychain_access_group == "4G6X3KNZUS.com.clavis.shared"

    # 12. Single profile only -> unprovisioned when optional, error when required.
    prov_single = resolve_provisioning(
        r2,
        discovered_profiles=[app_newer, agent_expired, agent_wrong_cert],
        require_provisioning=False,
        now_ts=now_ts,
    )
    assert prov_single.mode == "unprovisioned"
    assert prov_single.app_profile == ""
    assert prov_single.agent_profile == ""
    assert prov_single.keychain_access_group == ""

    try:
        resolve_provisioning(
            r2,
            discovered_profiles=[app_newer, agent_expired],
            require_provisioning=True,
            now_ts=now_ts,
        )
        raise AssertionError("expected ResolutionError when require_provisioning=True and agent profile missing")
    except ResolutionError as err:
        assert AGENT_BUNDLE_ID in str(err)

    # 13. Explicit profile enforcement: partial explicit pair or invalid explicit profile fails closed.
    try:
        resolve_provisioning(r2, app_profile=app_newer.path, agent_profile="", now_ts=now_ts)
        raise AssertionError("expected ResolutionError for single explicit --app-profile")
    except ResolutionError:
        pass

    profile_map = {
        app_newer.path: app_newer,
        agent_valid.path: agent_valid,
        parsed_ios.path: parsed_ios,
        agent_expired.path: agent_expired,
        agent_wrong_cert.path: agent_wrong_cert,
    }
    prov_explicit = resolve_provisioning(
        r2,
        app_profile=app_newer.path,
        agent_profile=agent_valid.path,
        profile_loader=profile_map.__getitem__,
        now_ts=now_ts,
    )
    assert prov_explicit.mode == "data-protection"
    assert prov_explicit.app_profile == app_newer.path
    assert prov_explicit.agent_profile == agent_valid.path

    for bad_agent in (parsed_ios.path, agent_expired.path, agent_wrong_cert.path):
        try:
            resolve_provisioning(
                r2,
                app_profile=app_newer.path,
                agent_profile=bad_agent,
                profile_loader=profile_map.__getitem__,
                now_ts=now_ts,
            )
            raise AssertionError(f"expected ResolutionError for invalid explicit agent profile {bad_agent}")
        except ResolutionError:
            pass

    # 14. Ad-hoc cannot enable provisioning; fails if require_provisioning=True.
    prov_adhoc = resolve_provisioning(r6, discovered_profiles=[app_newer, agent_valid], now_ts=now_ts)
    assert prov_adhoc.mode == "unprovisioned"
    try:
        resolve_provisioning(r6, require_provisioning=True, now_ts=now_ts)
        raise AssertionError("expected ResolutionError for ad-hoc with require_provisioning=True")
    except ResolutionError:
        pass

    # 15. Wildcard macOS Team Provisioning Profile satisfies both bundles; explicit App ID still wins when present.
    mac_wildcard = parse_provisioning_plist(
        {
            "UUID": "uuid-mac-wildcard",
            "Name": "Mac Team Provisioning Profile: *",
            "TeamIdentifier": ["4G6X3KNZUS"],
            "Platform": ["OSX"],
            "ExpirationDate": future_dt,
            "DeveloperCertificates": [fake_cert_der],
            "ProvisionedDevices": ["HOST-UDID-1"],
            "Entitlements": {
                "com.apple.application-identifier": "4G6X3KNZUS.*",
                "keychain-access-groups": ["4G6X3KNZUS.*", "com.apple.token"],
            },
        },
        path="/tmp/MacWildcard.provisionprofile",
    )
    assert mac_wildcard.provisioned_devices == frozenset({"HOST-UDID-1"})
    assert not mac_wildcard.provisions_all_devices

    r_fake_dev = ResolvedSigning(
        sign_arg=fake_cert_sha1,
        sign_cn="Apple Development: test@example.com",
        sign_team_id="4G6X3KNZUS",
        sign_label="test",
        timestamp_flag="--timestamp=none",
    )
    prov_wild = resolve_provisioning(
        r_fake_dev,
        discovered_profiles=[mac_wildcard],
        now_ts=now_ts,
        local_udid="HOST-UDID-1",
    )
    assert prov_wild.mode == "data-protection"
    assert prov_wild.app_profile == mac_wildcard.path
    assert prov_wild.agent_profile == mac_wildcard.path
    assert prov_wild.keychain_access_group == "4G6X3KNZUS.com.clavis.shared"

    # Explicit App ID profile wins over newer/older wildcard when both match.
    explicit_app_newer_or_older = ProvisioningProfile(
        path="/tmp/ExplicitApp.provisionprofile",
        uuid="u-exp-app",
        name="Explicit App",
        app_id="4G6X3KNZUS.com.clavis.app",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({fake_cert_sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("OSX",),
        expires_ts=now_ts + 100.0,
        expires_str="2027-01-15 08:01:40Z",
        provisioned_devices=frozenset({"HOST-UDID-1"}),
    )
    prov_pref = resolve_provisioning(
        r_fake_dev,
        discovered_profiles=[mac_wildcard, explicit_app_newer_or_older],
        now_ts=now_ts,
        local_udid="HOST-UDID-1",
    )
    assert prov_pref.mode == "data-protection"
    assert prov_pref.app_profile == explicit_app_newer_or_older.path
    assert prov_pref.agent_profile == mac_wildcard.path

    # 16. Development profile rejects mismatched host UDID; ProvisionsAllDevices passes regardless of UDID.
    prov_wrong_udid = resolve_provisioning(
        r_fake_dev,
        discovered_profiles=[mac_wildcard],
        now_ts=now_ts,
        local_udid="OTHER-UDID",
    )
    assert prov_wrong_udid.mode == "unprovisioned"

    dev_id_wildcard = ProvisioningProfile(
        path="/tmp/DevIDAllDevices.provisionprofile",
        uuid="u-devid-all",
        name="DevID All",
        app_id="4G6X3KNZUS.com.clavis.app",
        team_ids=("4G6X3KNZUS",),
        cert_sha1s=frozenset({fake_cert_sha1}),
        keychain_access_groups=("4G6X3KNZUS.com.clavis.shared",),
        platforms=("OSX",),
        expires_ts=now_ts + 100.0,
        expires_str="2027-01-15 08:01:40Z",
        provisions_all_devices=True,
        provisioned_devices=frozenset({"HOST-UDID-1"}),
    )
    assert profile_matches(
        dev_id_wildcard,
        bundle_id=APP_BUNDLE_ID,
        team_id="4G6X3KNZUS",
        cert_sha1=fake_cert_sha1,
        shared_group="4G6X3KNZUS.com.clavis.shared",
        now_ts=now_ts,
        local_udid="ANY-MAC-UDID",
    )

    print("✅ resolve-signing-identity self-tests passed (16/16).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve macOS code-signing identity and timestamp policy.")
    parser.add_argument("--keychain", default="", help="Keychain path to search (default: keychain search list)")
    parser.add_argument("--requested", default="", help="Explicit CLAVIS_SIGN_IDENTITY value")
    parser.add_argument("--preferred-team-id", default="4G6X3KNZUS", help="Preferred 10-char Team ID")
    parser.add_argument("--expected-team-id", default="", help="Required 10-char Team ID")
    parser.add_argument("--notarize", default="0", help="1 if notarization is enabled")
    parser.add_argument("--allow-adhoc", default="0", help="1 to allow '-' ad-hoc fallback when no cert exists")
    parser.add_argument("--timestamp-mode", default="auto", help="auto | secure | none")
    parser.add_argument("--app-profile", default="", help="Explicit macOS provisioning profile for com.clavis.app")
    parser.add_argument("--agent-profile", default="", help="Explicit macOS provisioning profile for com.clavis.agent")
    parser.add_argument("--require-provisioning", default="0", help="1 to fail if Data Protection provisioning pair is missing")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--shell", action="store_true", help="Emit shell variable assignments (default)")
    mode.add_argument("--status", action="store_true", help="Print diagnostic summary")
    mode.add_argument("--self-test", action="store_true", help="Run internal unit tests and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0

    notarize = args.notarize == "1"
    allow_adhoc = args.allow_adhoc == "1"
    require_provisioning = args.require_provisioning == "1"
    identities = load_identities(args.keychain)

    if args.status:
        return print_status(
            identities,
            keychain=args.keychain,
            requested=args.requested,
            preferred_team_id=args.preferred_team_id,
            expected_team_id=args.expected_team_id,
            notarize=notarize,
            allow_adhoc=allow_adhoc,
            timestamp_mode=args.timestamp_mode,
            app_profile=args.app_profile,
            agent_profile=args.agent_profile,
            require_provisioning=require_provisioning,
        )

    try:
        resolved = select_identity(
            identities,
            requested=args.requested,
            preferred_team_id=args.preferred_team_id,
            expected_team_id=args.expected_team_id,
            notarize=notarize,
            allow_adhoc=allow_adhoc,
            timestamp_mode=args.timestamp_mode,
        )
        provisioning = resolve_provisioning(
            resolved,
            app_profile=args.app_profile,
            agent_profile=args.agent_profile,
            require_provisioning=require_provisioning,
        )
    except ResolutionError as err:
        print(str(err), file=sys.stderr)
        return 1

    print(f"SIGN_ARG={shlex.quote(resolved.sign_arg)}")
    print(f"SIGN_CN={shlex.quote(resolved.sign_cn)}")
    print(f"SIGN_TEAM_ID={shlex.quote(resolved.sign_team_id)}")
    print(f"SIGN_LABEL={shlex.quote(resolved.sign_label)}")
    print(f"TIMESTAMP_FLAG={shlex.quote(resolved.timestamp_flag)}")
    print(f"PROVISION_MODE={shlex.quote(provisioning.mode)}")
    print(f"APP_PROVISION_PROFILE={shlex.quote(provisioning.app_profile)}")
    print(f"AGENT_PROVISION_PROFILE={shlex.quote(provisioning.agent_profile)}")
    print(f"KEYCHAIN_ACCESS_GROUP={shlex.quote(provisioning.keychain_access_group)}")
    print(f"DESIGNATED_REQ={shlex.quote(resolved.designated_req)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
