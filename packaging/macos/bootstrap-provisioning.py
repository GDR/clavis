#!/usr/bin/env python3
"""Bootstrap local macOS Data Protection provisioning profile(s) via Xcode Automatic Signing."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent

TEAM_ID_RE = re.compile(r"^[A-Z0-9]{10}$")
USER_PROFILE_DIR = Path.home() / "Library/Developer/Xcode/UserData/Provisioning Profiles"


def build_minimal_pbxproj(team_id: str) -> str:
    """Return a minimal valid macOS app project.pbxproj for Xcode automatic provisioning."""
    return f"""// !$*UTF8*$!
{{
\tarchiveVersion = 1;
\tclasses = {{
\t}};
\tobjectVersion = 56;
\tobjects = {{

/* Begin PBXBuildFile section */
\t\tA10000000000000000000001 /* main.c in Sources */ = {{isa = PBXBuildFile; fileRef = A10000000000000000000002 /* main.c */; }};
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
\t\tA10000000000000000000002 /* main.c */ = {{isa = PBXFileReference; lastKnownFileType = sourcecode.c.c; path = main.c; sourceTree = "<group>"; }};
\t\tA10000000000000000000003 /* Bootstrap.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = Bootstrap.app; sourceTree = BUILT_PRODUCTS_DIR; }};
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
\t\tA10000000000000000000004 /* Frameworks */ = {{
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
\t\tA10000000000000000000005 = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\tA10000000000000000000002 /* main.c */,
\t\t\t\tA10000000000000000000006 /* Products */,
\t\t\t);
\t\t\tsourceTree = "<group>";
\t\t}};
\t\tA10000000000000000000006 /* Products */ = {{
\t\t\tisa = PBXGroup;
\t\t\tchildren = (
\t\t\t\tA10000000000000000000003 /* Bootstrap.app */,
\t\t\t);
\t\t\tname = Products;
\t\t\tsourceTree = "<group>";
\t\t}};
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
\t\tA10000000000000000000007 /* Bootstrap */ = {{
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = A1000000000000000000000D /* Build configuration list for PBXNativeTarget "Bootstrap" */;
\t\t\tbuildPhases = (
\t\t\t\tA10000000000000000000009 /* Sources */,
\t\t\t\tA10000000000000000000004 /* Frameworks */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = Bootstrap;
\t\t\tproductName = Bootstrap;
\t\t\tproductReference = A10000000000000000000003 /* Bootstrap.app */;
\t\t\tproductType = "com.apple.product-type.application";
\t\t}};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
\t\tA10000000000000000000008 /* Project object */ = {{
\t\t\tisa = PBXProject;
\t\t\tattributes = {{
\t\t\t\tBuildIndependentTargetsInParallel = 1;
\t\t\t\tLastUpgradeCheck = 1600;
\t\t\t\tTargetAttributes = {{
\t\t\t\t\tA10000000000000000000007 = {{
\t\t\t\t\t\tCreatedOnToolsVersion = 16.0;
\t\t\t\t\t\tProvisioningStyle = Automatic;
\t\t\t\t\t\tDevelopmentTeam = {team_id};
\t\t\t\t\t}};
\t\t\t\t}};
\t\t\t}};
\t\t\tbuildConfigurationList = A1000000000000000000000C /* Build configuration list for PBXProject "ClavisProvision" */;
\t\t\tcompatibilityVersion = "Xcode 14.0";
\t\t\tdevelopmentRegion = en;
\t\t\thasScannedForEncodings = 0;
\t\t\tknownRegions = (
\t\t\t\ten,
\t\t\t);
\t\t\tmainGroup = A10000000000000000000005;
\t\t\tproductRefGroup = A10000000000000000000006 /* Products */;
\t\t\tprojectDirPath = "";
\t\t\tprojectRoot = "";
\t\t\ttargets = (
\t\t\t\tA10000000000000000000007 /* Bootstrap */,
\t\t\t);
\t\t}};
/* End PBXProject section */

/* Begin PBXSourcesBuildPhase section */
\t\tA10000000000000000000009 /* Sources */ = {{
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t\tA10000000000000000000001 /* main.c in Sources */,
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXSourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
\t\tA1000000000000000000000A /* Debug */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
\t\t\t\tALWAYS_SEARCH_USER_PATHS = NO;
\t\t\t\tCLANG_ENABLE_MODULES = YES;
\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tMACOSX_DEPLOYMENT_TARGET = 13.0;
\t\t\t\tONLY_ACTIVE_ARCH = YES;
\t\t\t\tSDKROOT = macosx;
\t\t\t}};
\t\t\tname = Debug;
\t\t}};
\t\tA1000000000000000000000B /* Debug */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
\t\t\t\tARCHS = arm64;
\t\t\t\tCODE_SIGN_IDENTITY = "Apple Development";
\t\t\t\tCODE_SIGN_STYLE = Automatic;
\t\t\t\tDEVELOPMENT_TEAM = {team_id};
\t\t\t\tGENERATE_INFOPLIST_FILE = YES;
\t\t\t\tINFOPLIST_KEY_LSUIElement = YES;
\t\t\t\tMACOSX_DEPLOYMENT_TARGET = 13.0;
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = com.clavis.app;
\t\t\t\tPRODUCT_NAME = Bootstrap;
\t\t\t\tSDKROOT = macosx;
\t\t\t}};
\t\t\tname = Debug;
\t\t}};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
\t\tA1000000000000000000000C /* Build configuration list for PBXProject "ClavisProvision" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\tA1000000000000000000000A /* Debug */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Debug;
\t\t}};
\t\tA1000000000000000000000D /* Build configuration list for PBXNativeTarget "Bootstrap" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\tA1000000000000000000000B /* Debug */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Debug;
\t\t}};
/* End XCConfigurationList section */

\t}};
\trootObject = A10000000000000000000008 /* Project object */;
}}
"""


def build_minimal_xcscheme() -> str:
    """Return a minimal shared Xcode scheme targeting Bootstrap so -destination platform=macOS works."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<Scheme
   LastUpgradeVersion = "1600"
   version = "1.7">
   <BuildAction
      parallelizeBuildables = "YES"
      buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry
            buildForTesting = "NO"
            buildForRunning = "YES"
            buildForProfiling = "NO"
            buildForArchiving = "NO"
            buildForAnalyzing = "NO">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "A10000000000000000000007"
               BuildableName = "Bootstrap.app"
               BlueprintName = "Bootstrap"
               ReferencedContainer = "container:ClavisProvision.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <LaunchAction
      buildConfiguration = "Debug"
      selectedDebuggerIdentifier = ""
      selectedLauncherIdentifier = "Xcode.IDEFoundation.Launcher.PosixSpawn"
      launchStyle = "0"
      useCustomWorkingDirectory = "NO"
      ignoresPersistentStateOnLaunch = "NO"
      debugDocumentVersioning = "YES"
      debugServiceExtension = "internal"
      allowLocationSimulation = "YES">
   </LaunchAction>
</Scheme>
"""


def has_xcode_developer_account() -> bool:
    """Return True if Xcode has a signed-in Apple Developer account configured."""
    if not os.path.exists("/usr/bin/xcodebuild"):
        return False
    proc = subprocess.run(
        ["/usr/bin/defaults", "read", "com.apple.dt.Xcode", "DVTDeveloperAccountManagerAppleIDLists"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and "identifier =" in proc.stdout


def extract_profile_uuid(profile_path: Path) -> str:
    proc = subprocess.run(
        ["/usr/bin/security", "cms", "-D", "-i", str(profile_path)],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(f"Failed to decode provisioning profile {profile_path}")
    data = plistlib.loads(proc.stdout)
    uuid = str(data.get("UUID") or "").strip()
    if not uuid:
        raise RuntimeError(f"Missing UUID inside provisioning profile {profile_path}")
    return uuid


def install_embedded_profile(embedded_path: Path, dest_dir: Path = USER_PROFILE_DIR) -> Path:
    uuid = extract_profile_uuid(embedded_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"{uuid}.provisionprofile"
    shutil.copyfile(embedded_path, target)
    os.chmod(target, 0o644)
    return target


def write_shared_keychain_entitlements(path: Path) -> None:
    content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.clavis.shared</string>
    </array>
</dict>
</plist>
"""
    path.write_text(content, encoding="utf-8")


def _load_resolver():
    import importlib.util

    resolver_path = SCRIPT_DIR / "resolve-signing-identity.py"
    spec = importlib.util.spec_from_file_location("resolve_signing_identity", resolver_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_signing_identity"] = mod
    spec.loader.exec_module(mod)
    return mod


def run_xcodebuild(
    *,
    proj_dir: Path,
    bundle_id: str,
    team_id: str,
    entitlements_path: Path | None,
) -> tuple[int, str, Path | None]:
    symroot = proj_dir / "build"
    derived = proj_dir / "dd"
    if symroot.exists():
        shutil.rmtree(symroot)
    if derived.exists():
        shutil.rmtree(derived)

    cmd = [
        "/usr/bin/xcodebuild",
        "-project",
        str(proj_dir / "ClavisProvision.xcodeproj"),
        "-scheme",
        "Bootstrap",
        "-configuration",
        "Debug",
        "-destination",
        "platform=macOS",
        "-derivedDataPath",
        str(derived),
        "-allowProvisioningUpdates",
        "-allowProvisioningDeviceRegistration",
        f"SYMROOT={symroot}",
        f"DEVELOPMENT_TEAM={team_id}",
        f"PRODUCT_BUNDLE_IDENTIFIER={bundle_id}",
    ]
    if entitlements_path is not None:
        cmd.append(f"CODE_SIGN_ENTITLEMENTS={entitlements_path}")
    cmd.append("build")

    env = dict(os.environ)
    env.pop("SDKROOT", None)
    proc = subprocess.run(cmd, env=env, text=True, capture_output=True, check=False)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    embedded = symroot / "Debug" / "Bootstrap.app" / "Contents" / "embedded.provisionprofile"
    return proc.returncode, output, embedded if embedded.is_file() else None


def bootstrap_provisioning(*, team_id: str, quiet_if_unavailable: bool = False) -> int:
    if not TEAM_ID_RE.fullmatch(team_id):
        print(f"❌ Invalid Team ID '{team_id}'. Expected 10 uppercase alphanumeric characters.", file=sys.stderr)
        return 1

    resolver = _load_resolver()
    identities = resolver.load_identities()
    try:
        resolved = resolver.select_identity(
            identities,
            preferred_team_id=team_id,
            expected_team_id=team_id,
        )
    except resolver.ResolutionError as err:
        if quiet_if_unavailable:
            return 0
        print(str(err), file=sys.stderr)
        return 1

    current_prov = resolver.resolve_provisioning(resolved)
    if current_prov.mode == "data-protection":
        print(f"✅ Data Protection provisioning already active (group: {current_prov.keychain_access_group}).")
        return 0

    if not has_xcode_developer_account():
        if quiet_if_unavailable:
            return 0
        print(
            "❌ No signed-in Apple Developer account found in Xcode. Sign in via Xcode -> Settings -> Accounts first.",
            file=sys.stderr,
        )
        return 1

    print(f"🔏 Bootstrapping macOS Data Protection provisioning profile(s) for team {team_id} via Xcode...")
    installed_paths: list[Path] = []
    strategy_errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="clavis-provision-") as tmp:
        tmp_path = Path(tmp)
        xcodeproj = tmp_path / "ClavisProvision.xcodeproj"
        schemes_dir = xcodeproj / "xcshareddata" / "xcschemes"
        schemes_dir.mkdir(parents=True, exist_ok=True)
        (xcodeproj / "project.pbxproj").write_text(build_minimal_pbxproj(team_id), encoding="utf-8")
        (schemes_dir / "Bootstrap.xcscheme").write_text(build_minimal_xcscheme(), encoding="utf-8")
        (tmp_path / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        entitlements = tmp_path / "shared.entitlements"
        write_shared_keychain_entitlements(entitlements)

        # Strategy A: Explicit App IDs for com.clavis.app and com.clavis.agent.
        strategy_a_ok = True
        for bundle_id in (resolver.APP_BUNDLE_ID, resolver.AGENT_BUNDLE_ID):
            rc, out, embedded = run_xcodebuild(
                proj_dir=tmp_path,
                bundle_id=bundle_id,
                team_id=team_id,
                entitlements_path=entitlements,
            )
            if rc == 0 and embedded is not None:
                installed = install_embedded_profile(embedded)
                installed_paths.append(installed)
                print(f"  ✅ Installed profile for {bundle_id}: {installed.name}")
            else:
                strategy_a_ok = False
                tail = "\n".join(line for line in out.strip().splitlines()[-12:] if line.strip())
                strategy_errors.append(f"[{bundle_id}] rc={rc}\n{tail}")
                break

        # Strategy B: Fall back to Xcode wildcard Mac Team Provisioning Profile (*).
        if not strategy_a_ok:
            wildcard_bundle = f"io.github.gdr.clavis.wildcard.{team_id.lower()}"
            rc, out, embedded = run_xcodebuild(
                proj_dir=tmp_path,
                bundle_id=wildcard_bundle,
                team_id=team_id,
                entitlements_path=None,
            )
            if rc == 0 and embedded is not None:
                installed = install_embedded_profile(embedded)
                installed_paths.append(installed)
                print(f"  ✅ Installed wildcard macOS team profile: {installed.name}")
            else:
                tail = "\n".join(line for line in out.strip().splitlines()[-12:] if line.strip())
                strategy_errors.append(f"[wildcard {wildcard_bundle}] rc={rc} embedded={embedded is not None}\n{tail}")

    final_prov = resolver.resolve_provisioning(resolved)
    if final_prov.mode == "data-protection":
        print(f"✅ Data Protection provisioning ready (group: {final_prov.keychain_access_group}).")
        return 0

    if quiet_if_unavailable:
        return 0

    print("❌ Xcode did not produce a matching macOS Data Protection provisioning pair.", file=sys.stderr)
    if installed_paths:
        print(f"   Installed candidate(s): {[str(p) for p in installed_paths]}", file=sys.stderr)
    for err in strategy_errors:
        print(err, file=sys.stderr)
    return 1


def run_self_test() -> None:
    """Validate generated project.pbxproj and shared entitlements without calling Xcode or Apple servers."""
    with tempfile.TemporaryDirectory(prefix="clavis-prov-selftest-") as tmp:
        tmp_path = Path(tmp)
        pbx = tmp_path / "project.pbxproj"
        pbx.write_text(build_minimal_pbxproj("4G6X3KNZUS"), encoding="utf-8")
        res = subprocess.run(["/usr/bin/plutil", "-lint", str(pbx)], capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"plutil failed on project.pbxproj: {res.stdout} {res.stderr}"

        ent = tmp_path / "shared.entitlements"
        write_shared_keychain_entitlements(ent)
        res_ent = subprocess.run(["/usr/bin/plutil", "-lint", str(ent)], capture_output=True, text=True, check=False)
        assert res_ent.returncode == 0, f"plutil failed on shared.entitlements: {res_ent.stdout} {res_ent.stderr}"

        loaded_ent = plistlib.loads(ent.read_bytes())
        assert loaded_ent["keychain-access-groups"] == ["$(AppIdentifierPrefix)com.clavis.shared"]

    print("✅ bootstrap-provisioning self-tests passed (2/2).")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bootstrap macOS Data Protection provisioning profiles via Xcode.")
    parser.add_argument("--team-id", default="4G6X3KNZUS", help="10-character Apple Developer Team ID")
    parser.add_argument(
        "--quiet-if-unavailable",
        action="store_true",
        help="Exit 0 quietly if Xcode Developer Account or network provisioning is unavailable",
    )
    parser.add_argument("--self-test", action="store_true", help="Validate generated Xcode project syntax and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        run_self_test()
        return 0
    return bootstrap_provisioning(team_id=args.team_id, quiet_if_unavailable=args.quiet_if_unavailable)


if __name__ == "__main__":
    raise SystemExit(main())
