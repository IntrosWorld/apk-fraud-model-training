"""Build a bounded CICMalDroid APK feature table without executing APKs.

This development-side exporter imports the production static analyzer so training and
inference observe the same evidence. Benign APKs are streamed from a tar.gz one member
at a time and deleted immediately after analysis; the archive is never fully extracted.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import re
import sys
import tarfile
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


HASH_APK = re.compile(r"^[0-9a-fA-F]{64}\.apk$")
LIST_COLUMNS = (
    "permissions",
    "dangerous_permissions",
    "api_families",
    "yara_rules",
    "obfuscation_signals",
    "certificate_flags",
    "apkid_categories",
    "financial_keywords",
)


def _number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _short_permission(value: str) -> str:
    return str(value).rsplit(".", 1)[-1].strip()


def _finding_token(item, *keys) -> str:
    if isinstance(item, dict):
        for key in keys:
            if item.get(key):
                return str(item[key])
        return ""
    return str(item) if item is not None else ""


def feature_row(result: dict, *, label: int, family: str, source: str) -> dict:
    """Convert an analyzer result into model-safe evidence; never include raw IOCs."""
    manifest = result.get("manifest") or {}
    permissions = result.get("permissions") or {}
    apis = result.get("apis") or {}
    iocs = result.get("iocs") or {}
    obfuscation = result.get("obfuscation") or {}
    yara = result.get("yara") or {}
    apkid = result.get("apkid") or {}
    certificate = result.get("certificate") or {}
    components = result.get("components") or {}
    coverage = result.get("analysis_coverage") or {}

    all_permissions = sorted({_short_permission(p) for p in permissions.get("all_permissions", []) if p})
    dangerous = permissions.get("dangerous") or []
    api_findings = apis.get("suspicious_apis") or []
    obf_signals = obfuscation.get("signals") or []
    yara_matches = yara.get("matches") or []
    apkid_findings = apkid.get("findings") or []
    counts = iocs.get("counts") or {}

    sha256 = str((result.get("file") or {}).get("sha256") or result.get("sha256") or "").lower()
    package_name = str(manifest.get("package_name") or "")
    cert_sha256 = str(certificate.get("sha256") or "").lower()
    group_id = package_name.casefold() or cert_sha256 or sha256
    row = {
        "sha256": sha256,
        "label": int(label),
        "family": family,
        "group_id": group_id,
        "source": source,
        "analysis_quality": str(result.get("analysis_quality") or "failed"),
        "package_present": int(bool(package_name)),
        "min_sdk": _number(manifest.get("min_sdk")),
        "target_sdk": _number(manifest.get("target_sdk")),
        "activities": _number((manifest.get("counts") or {}).get("activities")),
        "services": _number((manifest.get("counts") or {}).get("services")),
        "receivers": _number((manifest.get("counts") or {}).get("receivers")),
        "providers": _number((manifest.get("counts") or {}).get("providers")),
        "permission_count": len(all_permissions),
        "dangerous_permission_count": len(dangerous),
        "dangerous_permission_raw_points": sum(_number(item.get("score")) for item in dangerous),
        "api_count": len(api_findings),
        "api_scoreable_count": sum(_number(item.get("score")) > 0 for item in api_findings),
        "api_raw_points": sum(_number(item.get("score")) for item in api_findings),
        "url_count": _number(counts.get("urls")),
        "suspicious_url_count": _number(counts.get("suspicious_urls")),
        "ip_count": _number(counts.get("ips")),
        "domain_count": _number(counts.get("domains")),
        "keyword_count": _number(counts.get("keywords")),
        "financial_keyword_count": _number(counts.get("financial_keywords")),
        "decoded_blob_count": _number(counts.get("decoded_blobs")),
        "obfuscation_signal_count": len(obf_signals),
        "obfuscation_raw_points": _number(obfuscation.get("score")),
        "yara_match_count": len(yara_matches),
        "yara_raw_points": _number(yara.get("score")),
        "apkid_finding_count": len(apkid_findings),
        "apkid_raw_points": _number(apkid.get("score")),
        "certificate_present": int(bool(certificate.get("present"))),
        "certificate_flag_count": len(certificate.get("flags") or []),
        "certificate_validity_years": _number(certificate.get("validity_years")),
        "certificate_self_signed": int(bool(certificate.get("self_signed"))),
        "exported_component_count": _number(components.get("count")),
        "unguarded_exported_count": _number(components.get("unguarded_count")),
        "dex_string_count": _number(coverage.get("dex_strings")),
        "dex_control_flow": int(bool(coverage.get("dex_control_flow"))),
        "native_string_count": _number(iocs.get("native_strings_scanned")),
        "permissions": all_permissions,
        "dangerous_permissions": sorted({str(item.get("name")) for item in dangerous if item.get("name")}),
        "api_families": sorted({token for item in api_findings if (token := _finding_token(item, "api", "name", "pattern", "behaviour", "behavior"))}),
        "yara_rules": sorted({str(item.get("rule")) for item in yara_matches if item.get("rule")}),
        "obfuscation_signals": sorted({str(item.get("signal")) for item in obf_signals if item.get("signal")}),
        "certificate_flags": sorted({token for item in (certificate.get("flags") or []) if (token := _finding_token(item, "flag", "name", "reason"))}),
        "apkid_categories": sorted({str(item.get("category")) for item in apkid_findings if item.get("category")}),
        "financial_keywords": sorted({str(item) for item in (iocs.get("financial_keywords") or [])}),
    }
    return row


def _write_checkpoint(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")


def _read_checkpoint(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _deduplicate_rows(rows: list[dict]) -> list[dict]:
    """Preserve the first complete row for each computed APK content hash."""
    unique = []
    seen = set()
    for row in rows:
        sha256 = str(row.get("sha256") or "").lower()
        if not sha256 or sha256 in seen:
            continue
        seen.add(sha256)
        unique.append(row)
    return unique


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _analyse_worker(task: tuple[str, str]) -> dict:
    """Run one static analysis in an isolated worker process."""
    backend_root, apk_path = task
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass
    try:
        from app.analyzer.static_analyzer import analyze
        return analyze(apk_path)
    except Exception as exc:
        return {"valid_apk": False, "errors": [f"worker failure: {exc}"]}


def _valid_benign_member(member: tarfile.TarInfo) -> str | None:
    if not member.isfile() or member.size <= 0 or member.size > 100 * 1024 * 1024:
        return None
    parts = member.name.replace("\\", "/").strip("/").split("/")
    if len(parts) != 2 or parts[0].casefold() != "benign" or not HASH_APK.fullmatch(parts[1]):
        return None
    return parts[1].lower()


def _analyse_banking(analyze, directory: Path, wanted: int, seed: int, done: set[str], checkpoint: Path) -> None:
    candidates = sorted(directory.glob("*.apk"))
    random.Random(seed).shuffle(candidates)
    completed = 0
    for path in candidates:
        source_name = path.stem.lower()
        # Some extracted CIC archive filenames do not equal the current file-content
        # hash. Deduplicate on computed content identity, never the source filename.
        sha = _sha256_file(path)
        if sha in done:
            continue
        result = analyze(str(path))
        if result.get("valid_apk"):
            row = feature_row(result, label=1, family="Banking", source="CICMalDroid-2020")
            row["source_member"] = source_name
            _write_checkpoint(checkpoint, row)
            done.add(str(row["sha256"]))
            completed += 1
            print(f"Banking {completed}/{wanted}: {source_name}", flush=True)
        if completed >= wanted:
            break


def _analyse_benign(
    archive: Path,
    wanted: int,
    skip: int,
    done: set[str],
    checkpoint: Path,
    backend_root: Path,
    workers: int,
) -> None:
    completed = 0
    eligible = 0
    batch = []

    def process_batch(pool) -> None:
        nonlocal completed
        if not batch:
            return
        tasks = [(str(backend_root), str(item["path"])) for item in batch]
        results = list(pool.map(_analyse_worker, tasks))
        for item, result in zip(batch, results):
            try:
                if result.get("valid_apk"):
                    row = feature_row(result, label=0, family="Benign", source="CICMalDroid-2020")
                    row["source_member"] = item["sha"]
                    _write_checkpoint(checkpoint, row)
                    done.add(str(row["sha256"]))
                    completed += 1
                    print(f"Benign {completed}/{wanted}: {item['sha']}", flush=True)
            finally:
                item["path"].unlink(missing_ok=True)
        batch.clear()

    with (
        tempfile.TemporaryDirectory(prefix="maldroid-benign-") as temporary,
        tarfile.open(archive, "r|gz") as tar,
        ProcessPoolExecutor(max_workers=max(1, workers)) as pool,
    ):
        root = Path(temporary)
        for member in tar:
            filename = _valid_benign_member(member)
            if filename is None:
                continue
            if eligible < skip:
                eligible += 1
                continue
            eligible += 1
            sha = filename[:-4]
            if sha in done:
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            path = root / filename
            digest = hashlib.sha256()
            with path.open("wb") as target:
                while chunk := source.read(1024 * 1024):
                    target.write(chunk)
                    digest.update(chunk)
            source.close()
            if digest.hexdigest() != sha:
                path.unlink(missing_ok=True)
                continue
            batch.append({"path": path, "sha": sha})
            target_batch_size = min(max(1, workers * 2), wanted - completed)
            if len(batch) >= target_batch_size:
                process_batch(pool)
            if completed >= wanted:
                break
        process_batch(pool)


def _write_csv(rows: list[dict], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) + sorted(set().union(*(row.keys() for row in rows)) - set(rows[0]))
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            encoded = {column: row.get(column, "") for column in fieldnames}
            for column in LIST_COLUMNS:
                encoded[column] = json.dumps(encoded.get(column) or [], separators=(",", ":"))
            writer.writerow(encoded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-root", type=Path, required=True)
    parser.add_argument("--banking-dir", type=Path, required=True)
    parser.add_argument("--benign-archive", type=Path, required=True)
    parser.add_argument("--samples-per-class", type=int, default=100)
    parser.add_argument("--benign-skip", type=int, default=20, help="exclude the rule-calibration slice")
    parser.add_argument("--seed", type=int, default=2020)
    parser.add_argument("--workers", type=int, default=4, help="parallel static-analysis workers")
    parser.add_argument("--output", type=Path, default=Path("data/apk_static_features.csv"))
    args = parser.parse_args()

    backend_root = args.backend_root.resolve()
    sys.path.insert(0, str(backend_root))
    from app.analyzer.static_analyzer import analyze
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass

    checkpoint = args.output.with_suffix(".jsonl")
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    existing = _deduplicate_rows(_read_checkpoint(checkpoint))
    done = {str(row.get("sha256")) for row in existing}
    by_label = {label: sum(int(row.get("label", -1)) == label for row in existing) for label in (0, 1)}
    banking_needed = max(0, args.samples_per_class - by_label[1])
    benign_needed = max(0, args.samples_per_class - by_label[0])
    if banking_needed:
        _analyse_banking(analyze, args.banking_dir, banking_needed, args.seed, done, checkpoint)
    existing = _deduplicate_rows(_read_checkpoint(checkpoint))
    done = {str(row.get("sha256")) for row in existing}
    if benign_needed:
        _analyse_benign(
            args.benign_archive,
            benign_needed,
            args.benign_skip,
            done,
            checkpoint,
            backend_root,
            args.workers,
        )
    raw_checkpoint_rows = _read_checkpoint(checkpoint)
    checkpoint_rows = _deduplicate_rows(raw_checkpoint_rows)
    if not checkpoint_rows:
        raise RuntimeError("No valid APK features were generated")
    # A resumed checkpoint may contain more rows from one class. Publish an exactly
    # balanced, deterministic table even in that case.
    benign_rows = [row for row in checkpoint_rows if int(row.get("label", -1)) == 0][: args.samples_per_class]
    banking_rows = [row for row in checkpoint_rows if int(row.get("label", -1)) == 1][: args.samples_per_class]
    rows = benign_rows + banking_rows
    if len(benign_rows) < args.samples_per_class or len(banking_rows) < args.samples_per_class:
        raise RuntimeError("Could not generate the requested balanced class counts")
    _write_csv(rows, args.output)
    counts = {"benign": sum(row["label"] == 0 for row in rows), "banking": sum(row["label"] == 1 for row in rows)}
    metadata = {
        "created_at_epoch": int(time.time()),
        "rows": len(rows),
        "class_counts": counts,
        "seed": args.seed,
        "benign_skip": args.benign_skip,
        "static_only": True,
        "contains_apk_bytes": False,
        "contains_raw_iocs": False,
        "duplicate_checkpoint_rows_discarded": len(raw_checkpoint_rows) - len(checkpoint_rows),
    }
    args.output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
