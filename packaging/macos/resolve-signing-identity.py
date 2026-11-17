#!/usr/bin/env python3
"""Resolve an unambiguous macOS code-signing identity and timestamp policy."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import re
import shlex
import subprocess
import sys

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
class ResolvedSigning:
    sign_arg: str
    sign_cn: str
    sign_team_id: str
    sign_label: str
    timestamp_flag: str


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
) -> int:
    """Print keychain signing diagnostics; return 0 on success or 1 on failure."""
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

    print("✅ resolve-signing-identity self-tests passed (7/7).")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve macOS code-signing identity and timestamp policy.")
    parser.add_argument("--keychain", default="", help="Keychain path to search (default: keychain search list)")
    parser.add_argument("--requested", default="", help="Explicit CLAVIS_SIGN_IDENTITY value")
    parser.add_argument("--preferred-team-id", default="4G6X3KNZUS", help="Preferred 10-char Team ID")
    parser.add_argument("--expected-team-id", default="", help="Required 10-char Team ID")
    parser.add_argument("--notarize", default="0", help="1 if notarization is enabled")
    parser.add_argument("--allow-adhoc", default="0", help="1 to allow '-' ad-hoc fallback when no cert exists")
    parser.add_argument("--timestamp-mode", default="auto", help="auto | secure | none")
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
    except ResolutionError as err:
        print(str(err), file=sys.stderr)
        return 1

    print(f"SIGN_ARG={shlex.quote(resolved.sign_arg)}")
    print(f"SIGN_CN={shlex.quote(resolved.sign_cn)}")
    print(f"SIGN_TEAM_ID={shlex.quote(resolved.sign_team_id)}")
    print(f"SIGN_LABEL={shlex.quote(resolved.sign_label)}")
    print(f"TIMESTAMP_FLAG={shlex.quote(resolved.timestamp_flag)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
