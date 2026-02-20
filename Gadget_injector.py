#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GADGET INJECTOR — Frida Gadget injector for iOS 17/18 with Objection-friendly listen mode (v8)

Author: Saurabh
Email : saurabh77789@gmail.com

Highlights:
- Cyberpunk banner (magenta→cyan gradient) by default. Use --vibe to switch styles, --no-banner to suppress.
- Auto-detect host Frida version and fetch matching Gadget (fallback to latest).
- Safe ZIP extraction (Zip Slip defense), deterministic repack.
- Arch compatibility checks (arm64/arm64e) — robust across LIEF versions (no MachO.FAT dependency).
- --force overwrite / re-inject, --bundle-id targeting.
- Post-run guidance: resign & install (Sideloadly/AltStore/Xcode/CLI), start gadget on iOS 17/18,
  usbmux forward, Objection/Frida connect.

Usage:
  python3 gadget_injector.py <path/to/app.ipa> \
    [--frida-version auto|17.6.2] [--prefer-latest] [--gadget-name FridaGadget.dylib] \
    [--port 27042] [--bundle-id com.example.app] [--force] [--no-clean] \
    [--vibe cyberpunk|hacker|block|stealth|glitch|minimal] [--no-banner] [--debug]

For authorized testing only.
"""

import argparse
import json
import lzma
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from typing import List, Optional, Tuple, Dict, Set
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# =========================
# Banner / Vibe System
# =========================
def _supports_color() -> bool:
    """Detect if we should emit ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False

def _apply_gradient(lines, palette):
    """Apply a per-line gradient cycling through palette (list of ANSI codes)."""
    if not palette:
        return "\n".join(lines)
    out = []
    for i, line in enumerate(lines):
        color = palette[i % len(palette)]
        out.append(f"{color}{line}\033[0m")
    return "\n".join(out)

def _banner_ascii(vibe: str) -> str:
    if vibe == "hacker":
        return r"""
  ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____
 ||G |||A |||D |||G |||E |||T |||  |||I |||N |||J |||E |||C |||T ||
 ||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
 |/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
""".strip("\n")
    if vibe == "block":
        return r"""
 ██████   █████  ██████  ██████  ███████ ███████ ████████
██       ██   ██ ██   ██ ██   ██ ██      ██         ██
██   ███ ███████ ██████  ██████  █████   ███████    ██
██    ██ ██   ██ ██      ██      ██           ██    ██
 ██████  ██   ██ ██      ██      ███████ ███████    ██

                GADGET  INJECTOR
""".strip("\n")
    if vibe == "stealth":
        return "Gadget Injector"
    if vibe == "glitch":
        return "G A D G E T   I N J E C T O R\n/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\/\\"
    if vibe == "minimal":
        return "== Gadget Injector =="
    # default: cyberpunk
    return r"""
   ________        __         __    __  __           __
  / ____/ /___  __/ /_  _____/ /_  / / / /___  _____/ /_____  _____
 / / __/ / __ \/ / __ \/ ___/ __ \/ / / / __ \/ ___/ __/ __ \/ ___/
/ /_/ / / /_/ / / /_/ (__  ) / / / /_/ / /_/ / /  / /_/ /_/ / /
\____/_/\____/_/_.___/____/_/ /_/\____/ .___/_/   \__/\____/_/
                                     /_/      G A D G E T  I N J E C T O R
""".strip("\n")

def print_banner(vibe: str = "cyberpunk",
                 author: str = "Saurabh",
                 email: str = "saurabh77789@gmail.com",
                 enable_color: bool = True):
    # ANSI palettes
    CYAN = "\033[96m"; MAG = "\033[95m"; YEL = "\033[93m"; GRN = "\033[92m"
    RED = "\033[91m"; BLU = "\033[94m"; DIM = "\033[2m"; RST = "\033[0m"

    ascii_art_lines = _banner_ascii(vibe).splitlines()
    color_ok = enable_color and _supports_color()

    if vibe == "cyberpunk" and color_ok:
        palette = [MAG, CYAN, MAG, CYAN]  # magenta↔cyan
        art = _apply_gradient(ascii_art_lines, palette)
        details = f"{YEL}Author:{RST} {author}   {YEL}Email:{RST} {email}"
    elif vibe == "hacker" and color_ok:
        palette = [GRN]
        art = _apply_gradient(ascii_art_lines, palette)
        details = f"{GRN}Author:{RST} {author}   {GRN}Email:{RST} {email}"
    elif vibe == "block" and color_ok:
        palette = [YEL]
        art = _apply_gradient(ascii_art_lines, palette)
        details = f"{YEL}Author:{RST} {author}   {YEL}Email:{RST} {email}"
    elif vibe == "glitch" and color_ok:
        palette = [RED, BLU]
        art = _apply_gradient(ascii_art_lines, palette)
        details = f"{RED}Author:{RST} {author}   {BLU}Email:{RST} {email}"
    elif vibe == "minimal" and color_ok:
        palette = [CYAN]
        art = _apply_gradient(ascii_art_lines, palette)
        details = f"{DIM}Author:{RST} {author}   {DIM}Email:{RST} {email}"
    else:
        # stealth or no-color fallback
        art = "\n".join(ascii_art_lines)
        details = f"Author: {author}   Email: {email}"

    print("\n" + art + "\n")
    print(details + "\n")

# =========================
# Optional: import LIEF
# =========================
try:
    import lief  # type: ignore
except Exception:
    lief = None

def log(msg: str) -> None:
    print(f"[+] {msg}")

def warn(msg: str) -> None:
    print(f"[!] {msg}")

# =========================
# ZIP Handling (hardened)
# =========================
def unzip_ipa(ipa: str, out_dir: str) -> Dict[str, Set[str]]:
    top_dirs: Set[str] = set()
    top_files: Set[str] = set()

    with zipfile.ZipFile(ipa, "r") as z:
        names = z.namelist()
        for name in names:
            if "/" in name:
                top_dirs.add(name.split("/", 1)[0])
            else:
                top_files.add(name)

        for member in z.infolist():
            dest = os.path.abspath(os.path.join(out_dir, member.filename))
            if not dest.startswith(os.path.abspath(out_dir) + os.sep) and dest != os.path.abspath(out_dir):
                raise RuntimeError(f"Refusing to extract outside target dir: {member.filename}")
            z.extract(member, out_dir)

    return {"dirs": top_dirs, "files": top_files}

def zip_ipa(src_dir: str, out_ipa: str, original_manifest: Dict[str, Set[str]]) -> None:
    payload_dir = os.path.join(src_dir, "Payload")
    if not os.path.isdir(payload_dir):
        raise RuntimeError("Payload/ missing; cannot repack IPA")

    def _write_dir(z: zipfile.ZipFile, base_dir: str):
        for root, dirs, files in os.walk(base_dir):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, src_dir)
                if "__MACOSX" in rel.split(os.sep):
                    continue
                z.write(full, rel)

    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED) as z:
        _write_dir(z, payload_dir)
        for d in sorted(original_manifest.get("dirs", set())):
            if d == "Payload":
                continue
            abs_dir = os.path.join(src_dir, d)
            if os.path.isdir(abs_dir):
                _write_dir(z, abs_dir)
        for f in sorted(original_manifest.get("files", set())):
            abs_f = os.path.join(src_dir, f)
            if os.path.isfile(abs_f) and not f.startswith("__MACOSX"):
                z.write(abs_f, f)

# =========================
# Mach-O Helpers (LIEF)
# =========================
def _collect_rpaths(bin_obj) -> List[str]:
    rpaths: List[str] = []
    try:
        for rp in getattr(bin_obj, 'rpaths', []) or []:
            try:
                rpaths.append(rp.path)
            except Exception:
                pass
    except Exception:
        pass
    if not rpaths:
        for cmd in getattr(bin_obj, 'commands', []) or []:
            try:
                if isinstance(cmd, lief.MachO.RPathCommand):
                    rpaths.append(cmd.path)
            except Exception:
                pass
    return rpaths

def _collect_load_libraries(bin_obj) -> List[str]:
    libs: List[str] = []
    for lib in getattr(bin_obj, 'libraries', []) or []:
        try:
            s = str(lib)
            if s and s not in libs:
                libs.append(s)
            continue
        except Exception:
            pass
        try:
            name = lib.name
            if name and name not in libs:
                libs.append(name)
        except Exception:
            pass
    return libs

def macho_arch_set(path: str):
    """
    Return set of (cpu_type, cpu_subtype) for a Mach-O file (fat or thin).
    Version-agnostic: avoids hard dependencies on MachO.FAT / FatBinary.
    """
    if lief is None:
        return set()

    obj = lief.parse(path)
    arches = set()

    # 1) Many LIEF versions make fat binaries iterable (for b in obj)
    try:
        for b in obj:  # Will raise TypeError for thin binaries
            try:
                hdr = b.header
                arches.add((hdr.cpu_type, hdr.cpu_subtype))
            except Exception:
                pass
        if arches:
            return arches
    except TypeError:
        pass
    except Exception:
        pass

    # 2) Try common container attributes used across versions
    for attr in ("binaries", "arches", "fat_binaries"):
        bins = getattr(obj, attr, None)
        if bins:
            for b in bins:
                try:
                    hdr = b.header
                    arches.add((hdr.cpu_type, hdr.cpu_subtype))
                except Exception:
                    pass
            if arches:
                return arches

    # 3) Fallback: treat as thin Mach-O Binary
    try:
        hdr = obj.header
        arches.add((hdr.cpu_type, hdr.cpu_subtype))
    except Exception:
        pass

    return arches

def ensure_arch_compat(main_binary: str, gadget_path: str, debug: bool = False) -> None:
    if lief is None:
        warn("LIEF not available; skipping architecture compatibility check.")
        return
    app_arches = macho_arch_set(main_binary)
    gad_arches = macho_arch_set(gadget_path)
    if debug:
        log(f"App arches: {app_arches or '<unknown>'}")
        log(f"Gadget arches: {gad_arches or '<unknown>'}")
    if app_arches and gad_arches and not (app_arches & gad_arches):
        raise RuntimeError(f"Architecture mismatch: app {app_arches} vs gadget {gad_arches}")

def ensure_frameworks_and_paths(app_dir: str, gadget_src_path: str, gadget_name: str, force: bool = False) -> str:
    fw_dir = os.path.join(app_dir, "Frameworks")
    os.makedirs(fw_dir, exist_ok=True)
    dst = os.path.join(fw_dir, gadget_name)

    if os.path.abspath(gadget_src_path) != os.path.abspath(dst):
        if force and os.path.exists(dst):
            os.remove(dst)
        if not os.path.exists(dst):
            shutil.copy2(gadget_src_path, dst)
    os.chmod(
        dst,
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
        stat.S_IRGRP | stat.S_IXGRP |
        stat.S_IROTH | stat.S_IXOTH
    )
    return dst

def ensure_rpath_and_inject(binary_path: str, gadget_name: str, *, debug: bool = False, force: bool = False) -> None:
    if lief is None:
        raise RuntimeError("LIEF is required to modify Mach-O load commands. Please install python-lief.")

    bin_obj = lief.parse(binary_path)

    # Be tolerant of LIEF class name differences; rely on attribute access
    # rather than strict isinstance checks.

    if debug:
        log("== Before injection ==")
        try:
            log("Existing rpaths: " + (", ".join(_collect_rpaths(bin_obj)) or "<none>"))
            log("Existing libs: " + (", ".join(_collect_load_libraries(bin_obj)) or "<none>"))
        except Exception:
            pass

    wanted_rpath = "@executable_path/Frameworks"
    try:
        current_rpaths = _collect_rpaths(bin_obj)
        if wanted_rpath not in current_rpaths:
            bin_obj.add_rpath(wanted_rpath)
            log(f"Added rpath: {wanted_rpath}")
        else:
            log(f"rpath already present: {wanted_rpath}")
    except Exception as e:
        raise RuntimeError(f"Failed to ensure rpath: {e}")

    wanted_lib = "@rpath/" + gadget_name
    try:
        load_paths = _collect_load_libraries(bin_obj)
        already = [p for p in load_paths if gadget_name in p]

        if already and force:
            for p in already:
                try:
                    bin_obj.remove_library(p)
                    log(f"Removed existing load command: {p}")
                except Exception:
                    pass
            already = []

        if not already:
            bin_obj.add_library(wanted_lib)
            log(f"Injected load command: {wanted_lib}")
        else:
            log("Gadget load command already present")
    except Exception as e:
        raise RuntimeError(f"Failed to add Gadget load command: {e}")

    try:
        bin_obj.write(binary_path)
    except Exception as e:
        raise RuntimeError(f"Failed to write modified Mach-O: {e}")

    if debug:
        try:
            bin_obj2 = lief.parse(binary_path)
            log("== After injection ==")
            log("rpaths: " + (", ".join(_collect_rpaths(bin_obj2)) or "<none>"))
            log("libs: " + (", ".join(_collect_load_libraries(bin_obj2)) or "<none>"))
        except Exception:
            pass

# =========================
# App discovery
# =========================
def find_app_and_main_binary(payload_dir: str, bundle_id: Optional[str] = None, debug: bool = False):
    if not os.path.isdir(payload_dir):
        raise RuntimeError("Payload/ not found in extracted IPA")

    candidates: List[Tuple[str, str, str, str]] = []  # (app_dir, main_bin, exe_name, pkg_type)

    for entry in os.listdir(payload_dir):
        if not entry.endswith(".app"):
            continue
        app_dir = os.path.join(payload_dir, entry)
        info_plist = os.path.join(app_dir, "Info.plist")
        if not os.path.isfile(info_plist):
            continue
        try:
            with open(info_plist, "rb") as f:
                info = plistlib.load(f)
            exe_name = info.get("CFBundleExecutable")
            b_id = info.get("CFBundleIdentifier", "")
            pkg_type = info.get("CFBundlePackageType", "")
            if not exe_name:
                continue
            main_bin = os.path.join(app_dir, exe_name)
            if not os.path.isfile(main_bin):
                continue
            if bundle_id and b_id != bundle_id:
                continue
            candidates.append((app_dir, main_bin, exe_name, pkg_type or ""))
        except Exception:
            continue

    if not candidates:
        raise RuntimeError("Could not locate .app with CFBundleExecutable inside Payload/ (check --bundle-id?)")

    def sort_key(t):
        app_dir, main_bin, exe_name, pkg_type = t
        return (0 if pkg_type == "APPL" else 1, -os.path.getsize(main_bin))

    candidates.sort(key=sort_key)
    chosen = candidates[0]

    if debug:
        log("App candidates (top 5):")
        for t in candidates[:5]:
            app_dir, main_bin, exe_name, pkg_type = t
            log(f"  - {os.path.basename(app_dir)} | type={pkg_type or '<unknown>'} | bin={exe_name} | size={os.path.getsize(main_bin)}")
        log(f"Chosen .app: {os.path.basename(chosen[0])}")

    return chosen  # (app_dir, main_binary, exe_name, pkg_type)

# =========================
# Frida version resolution
# =========================
def detect_host_frida_version(debug: bool = False) -> Optional[str]:
    try:
        import frida  # type: ignore
        ver = getattr(frida, "__version__", None)
        if isinstance(ver, str) and ver.strip():
            if debug:
                log(f"Detected Frida (python) version: {ver}")
            return ver.strip()
    except Exception as e:
        if debug:
            warn(f"Python frida not detectable: {e}")

    try:
        out = subprocess.check_output(["frida", "--version"], stderr=subprocess.STDOUT, timeout=5)
        s = out.decode("utf-8", "ignore").strip()
        for token in s.replace("Frida", "").strip().split():
            if any(ch.isdigit() for ch in token) and "." in token:
                if debug:
                    log(f"Detected Frida (CLI) version: {token}")
                return token
        if debug:
            warn(f"Could not parse version from 'frida --version' output: {s}")
    except Exception as e:
        if debug:
            warn(f"CLI frida not detectable: {e}")

    return None

def github_latest_frida_version(timeout: int = 15, debug: bool = False) -> Optional[str]:
    url = "https://api.github.com/repos/frida/frida/releases/latest"
    try:
        req = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "frida-injector"}, method="GET")
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        js = json.loads(data.decode("utf-8", "ignore"))
        tag = js.get("tag_name") or js.get("name")
        if tag and isinstance(tag, str):
            tag = tag.strip()
            if debug:
                log(f"Latest Frida release tag detected from GitHub: {tag}")
            return tag
    except Exception as e:
        if debug:
            warn(f"Failed to query latest Frida release from GitHub: {e}")
    return None

def frida_gadget_asset_url(version: str) -> str:
    return f"https://github.com/frida/frida/releases/download/{version}/frida-gadget-{version}-ios-universal.dylib.xz"

def url_asset_exists(url: str, timeout: int = 15, debug: bool = False) -> bool:
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "frida-injector"})
        with urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            return 200 <= status < 300
    except HTTPError as e:
        if debug:
            warn(f"HEAD {url} -> HTTP {e.code}")
        return False
    except URLError as e:
        if debug:
            warn(f"HEAD {url} -> URL error {e}")
        return False
    except Exception as e:
        if debug:
            warn(f"HEAD {url} -> error {e}")
        return False

def resolve_frida_version(requested: Optional[str], prefer_latest: bool, debug: bool = False) -> Tuple[str, str]:
    if prefer_latest:
        latest = github_latest_frida_version(debug=debug)
        if latest:
            return latest, "latest (forced)"
        else:
            fallback = requested if (requested and requested != "auto") else "17.6.2"
            return fallback, "fallback (latest unavailable)"

    if requested and requested != "auto":
        candidate = requested.strip()
        asset = frida_gadget_asset_url(candidate)
        if url_asset_exists(asset, debug=debug):
            return candidate, "requested"
        else:
            latest = github_latest_frida_version(debug=debug)
            if latest:
                return latest, f"fallback to latest (asset missing for {candidate})"
            else:
                return candidate, "requested (asset existence not confirmed)"

    host_ver = detect_host_frida_version(debug=debug)
    if host_ver:
        asset = frida_gadget_asset_url(host_ver)
        if url_asset_exists(asset, debug=debug):
            return host_ver, "auto (host-detected)"
        else:
            latest = github_latest_frida_version(debug=debug)
            if latest:
                return latest, f"fallback to latest (asset missing for {host_ver})"
            else:
                return host_ver, "auto (host-detected; asset not confirmed)"

    latest = github_latest_frida_version(debug=debug)
    if latest:
        return latest, "latest (auto; host not detected)"
    return "17.6.2", "hardcoded fallback (no detection; latest API failed)"

# =========================
# Download Gadget
# =========================
def download_gadget(frida_version: str, out_path: str, timeout: int = 20) -> None:
    url = frida_gadget_asset_url(frida_version)
    log(f"Downloading Frida Gadget {frida_version}…")
    try:
        with urlopen(url, timeout=timeout) as resp:
            status = getattr(resp, "status", None)
            if status is not None and status != 200:
                raise RuntimeError(f"Failed to download Gadget: HTTP {status}")
            data = resp.read()
    except Exception as e:
        raise RuntimeError(f"Download failed for {url}: {e}")

    try:
        decompressed = lzma.decompress(data)
    except Exception as e:
        raise RuntimeError(f"Failed to decompress Gadget payload: {e}")

    with open(out_path, "wb") as f:
        f.write(decompressed)
    os.chmod(out_path, 0o755)

# =========================
# Signing clean-up
# =========================
def clean_signing_artifacts(app_dir: str) -> None:
    for d in ("_CodeSignature", "SC_Info"):
        p = os.path.join(app_dir, d)
        if os.path.isdir(p):
            shutil.rmtree(p)
            log(f"Removed {d}/ for clean resign")

# =========================
# Main
# =========================
def main():
    parser = argparse.ArgumentParser(description="Gadget Injector: Frida Gadget injection for iOS 17/18 with Objection-friendly listen mode.")
    parser.add_argument("ipa", help="Path to the input .ipa")
    parser.add_argument("-o", "--output", default=None, help="Output .ipa path")
    parser.add_argument("--frida-version", default="auto", help="Frida Gadget version tag, e.g., 17.6.2 (default: auto-detect host)")
    parser.add_argument("--prefer-latest", action="store_true", help="Ignore detection and use the latest release from GitHub")
    parser.add_argument("--gadget-name", default="FridaGadget.dylib", help="Name to use for the Gadget dylib (under Frameworks/)")
    parser.add_argument("--port", type=int, default=27042, help="TCP port for Gadget listen mode")
    parser.add_argument("--bundle-id", default=None, help="Target CFBundleIdentifier (if Payload contains multiple apps)")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing Gadget and re-inject load command")
    parser.add_argument("--no-clean", action="store_true", help="Do not remove _CodeSignature/ and SC_Info/")
    parser.add_argument("--vibe", choices=["cyberpunk", "hacker", "block", "stealth", "glitch", "minimal"], default="cyberpunk", help="Banner style vibe (default: cyberpunk)")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the startup banner (useful in CI)")
    parser.add_argument("--debug", action="store_true", help="Print verbose details (rpaths, libraries, candidates, version resolution)")

    args = parser.parse_args()

    if not args.no_banner:
        print_banner(vibe=args.vibe, author="Saurabh", email="saurabh77789@gmail.com", enable_color=True)

    ipa = os.path.abspath(args.ipa)
    if not os.path.isfile(ipa):
        print(f"[!] Input not found: {ipa}")
        sys.exit(1)

    out_ipa = args.output or (os.path.splitext(ipa)[0] + "-frida-listen.ipa")

    tmp = tempfile.mkdtemp(prefix="ipa_frida_")
    try:
        log("Extracting IPA…")
        manifest = unzip_ipa(ipa, tmp)

        payload = os.path.join(tmp, "Payload")
        app_dir, main_binary, exe_name, pkg_type = find_app_and_main_binary(payload, args.bundle_id, debug=args.debug)
        log(f".app: {os.path.basename(app_dir)} (type={pkg_type or '<unknown>'})")
        log(f"Main binary: {exe_name}")

        # Decide Frida Gadget version (auto-detect or latest)
        chosen_version, reason = resolve_frida_version(args.frida_version, args.prefer_latest, debug=args.debug)
        log(f"Frida Gadget version -> {chosen_version} ({reason})")

        # Download gadget to temp and place under Frameworks/
        gadget_tmp = os.path.join(tmp, args.gadget_name)
        if args.force and os.path.exists(gadget_tmp):
            os.remove(gadget_tmp)
        if not os.path.exists(gadget_tmp):
            download_gadget(chosen_version, gadget_tmp)
        else:
            log(f"Reusing downloaded Gadget at: {gadget_tmp}")

        # Arch compatibility check before copying
        ensure_arch_compat(main_binary, gadget_tmp, debug=args.debug)

        gadget_dst = ensure_frameworks_and_paths(app_dir, gadget_tmp, args.gadget_name, force=args.force)
        rel_dst = os.path.relpath(gadget_dst, app_dir)
        log(f"Gadget placed at: {rel_dst}")

        # Inject and ensure rpath
        ensure_rpath_and_inject(main_binary, args.gadget_name, debug=args.debug, force=args.force)

        # Objection-friendly Frida Gadget config (listen on TCP)
        config_name = os.path.splitext(args.gadget_name)[0] + ".config"
        config_path = os.path.join(app_dir, config_name)
        frida_cfg = """
{
  "interaction": { "type": "listen", "address": "127.0.0.1", "port": PORT_PLACEHOLDER },
  "code_signing": "required",
  "runtime": { "threaded": true },
  "logging": { "level": "error" },
  "teardown": "minimal",
  "resume": true
}
""".replace("PORT_PLACEHOLDER", str(args.port))
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(frida_cfg.strip() + "\n")
        log(f"Wrote config (listen mode on {args.port}): {config_name}")

        # Minimal bootstrap.js placeholder
        bootstrap_path = os.path.join(app_dir, "bootstrap.js")
        with open(bootstrap_path, "w", encoding="utf-8") as f:
            f.write("console.log('[*] Frida Gadget bootstrap loaded');\n")
        log("Wrote bootstrap.js")

        if not args.no_clean:
            clean_signing_artifacts(app_dir)

        log("Repacking IPA…")
        zip_ipa(tmp, out_ipa, manifest)
        log(f"Done → {out_ipa}")

        # ---- Post-run instructions (resign/install + start gadget) ----
        print("\n========== NEXT STEPS ==========")
        print("1) RESIGN & INSTALL (pick one):")
        print("   • Sideloadly (GUI): Open Sideloadly → drop the IPA → select your Apple ID → Advanced: Automatic re-sign → Start.")
        print("   • AltStore (GUI): AltStore → My Apps → + → choose IPA → Install.")
        print("   • Xcode/Dev: Re-sign all Frameworks/*.dylib (SAME TeamID, Gadget with NO entitlements), then the .app; install via Xcode Devices or ios-deploy.")
        print("   • CLI (isign/zsign/rcodesign): sign embedded → sign app → package → install.")
        print("")
        print("2) LAUNCH PAUSED on iOS 17/18 (recommended):")
        print("   xcrun devicectl device process launch --device <UDID> --start-stopped <bundle-id>")
        print("")
        print("3) USB PORT FORWARD (host ↔ device):")
        print(f"   pymobiledevice3 usbmux forward {args.port} {args.port}")
        print("")
        print("4) CONNECT:")
        print(f"   Objection: objection -N -h 127.0.0.1 -p {args.port} explore")
        print(f"   Frida CLI: frida -H 127.0.0.1:{args.port} -n <process-name>")
        print("================================\n")

    except Exception as e:
        warn(f"Failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()