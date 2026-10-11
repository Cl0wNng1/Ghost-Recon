"""
GHOST RECON v2.0 — Payload Registry Loader (ghost.py drop-in replacement)

Upgrades:
  1. RECURSIVE FLATTENING: The 12 expert-level YAML payloads are deeply nested
     (e.g., waf_bypass → vendor → config → payloads). This converts all nested
     structures into usable 1D lists for fuzzing modules.
  2. Robust YAML error handling: logs syntax errors without halting.
  3. Flat index accessible via ctx.payload_registry["__flat__"][category]
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Union

log = logging.getLogger("ghost.payloads")


def _recursive_flatten(data: Any, prefix: str = "", depth: int = 0) -> List[str]:
    """
    Recursively flatten any nested YAML structure into a 1D list of strings.
    
    Handles:
      - Nested dicts (e.g., waf_bypass → vendor_specific → cloudflare → [payloads])
      - Lists of dicts (e.g., [{name: ..., regex: ...}])
      - Lists of strings (leaf payloads)
      - Mixed types
    
    Returns a flat list of string payloads/patterns.
    """
    if depth > 20:  # Prevent infinite recursion on circular refs
        return []

    result: List[str] = []

    if isinstance(data, str):
        s = data.strip()
        if s:
            result.append(s)

    elif isinstance(data, (int, float, bool)):
        result.append(str(data))

    elif isinstance(data, list):
        for item in data:
            result.extend(_recursive_flatten(item, prefix, depth + 1))

    elif isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)

            # Special handling: if value contains 'regex' or 'template' or
            # 'fingerprint' keys, extract those directly
            if isinstance(value, str):
                result.append(value)
            elif isinstance(value, dict):
                # Extract known payload keys
                for payload_key in ("regex", "template", "fingerprint", "payload",
                                     "header", "value", "url", "query"):
                    if payload_key in value and isinstance(value[payload_key], str):
                        result.append(value[payload_key])
                # Recurse into remaining structure
                result.extend(_recursive_flatten(value, new_prefix, depth + 1))
            elif isinstance(value, list):
                result.extend(_recursive_flatten(value, new_prefix, depth + 1))

    return result


def _build_flat_index(registry: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Build a flat index from the full registry.
    Returns: {"xss": [...all xss payloads...], "sqli": [...], ...}
    """
    flat: Dict[str, List[str]] = {}
    for category, data in registry.items():
        if category == "__flat__":
            continue
        try:
            payloads = _recursive_flatten(data)
            # Deduplicate while preserving order
            seen = set()
            unique = []
            for p in payloads:
                if p not in seen:
                    seen.add(p)
                    unique.append(p)
            flat[category] = unique
        except Exception as e:
            log.warning(f"Failed to flatten {category}: {e}")
            flat[category] = []
    return flat


def load_payload_registry(payloads_dir: str, console: Any) -> Dict[str, Any]:
    """
    Load all YAML payload files into a single registry dict.
    
    Returns a dict with:
      - Top-level keys = YAML filenames (original nested structure)
      - "__flat__" key = recursive flattened 1D index per category
    
    Usage:
      registry = load_payload_registry("./payloads", console)
      xss_payloads = registry["__flat__"]["xss"]
      sqli_time = registry["sqli"]["time_based"]["mysql"]  # original nested
    """
    registry: Dict[str, Any] = {}
    pdir = Path(payloads_dir)
    if not pdir.is_dir():
        console.print(f"  [dim]Payloads directory not found: {payloads_dir}[/dim]")
        return registry

    try:
        import yaml as _yaml
    except ImportError:
        console.print(f"  [dim]PyYAML not installed — payload registry empty[/dim]")
        return registry

    # Load all YAML files
    errors = 0
    for yml_file in sorted(pdir.glob("*.yml")):
        try:
            raw = yml_file.read_text(encoding="utf-8", errors="replace")
            data = _yaml.safe_load(raw)
            if data:
                registry[yml_file.stem] = data
        except _yaml.YAMLError as e:
            errors += 1
            console.print(f"  [yellow]⚠[/yellow]  YAML syntax error in {yml_file.name}: {e}")
            log.warning(f"YAML syntax error in {yml_file.name}: {e}")
        except Exception as e:
            errors += 1
            console.print(f"  [yellow]⚠[/yellow]  Failed to load {yml_file.name}: {e}")
            log.warning(f"Failed to load {yml_file.name}: {e}")

    if not registry:
        return registry

    # Build flat index
    try:
        flat_index = _build_flat_index(registry)
        registry["__flat__"] = flat_index

        total_payloads = sum(len(v) for v in flat_index.values())
        categories = ", ".join(
            f"{k}({len(v)})" for k, v in sorted(flat_index.items())
        )
        console.print(
            f"  [green]✓[/green]  Payload registry: {len(registry) - 1} files, "
            f"{total_payloads} flattened payloads"
        )
        console.print(f"  [dim]Categories: {categories}[/dim]")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Flat index build failed: {e}")
        log.warning(f"Flat index build failed: {e}")

    if errors:
        console.print(f"  [yellow]⚠[/yellow]  {errors} file(s) had parse errors")

    return registry
