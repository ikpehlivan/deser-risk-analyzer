#!/usr/bin/env python3
import base64
import json
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

import click
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

JAVA_MAGIC = b"\xAC\xED\x00\x05"  # Java serialization stream header (common)
# .NET BinaryFormatter kesin bir magic değil; heuristic yaklaşım kullanacağız.
DOTNET_HINTS = [b"System.Runtime.Serialization", b"BinaryFormatter", b"System.Windows.Data"]

@dataclass
class Finding:
    severity: str
    title: str
    evidence: str
    recommendation: str

def load_signatures(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def decode_input(raw: str, is_base64: bool) -> bytes:
    if is_base64:
        return base64.b64decode(raw, validate=False)
    return raw.encode("utf-8", errors="ignore")

def detect_format(blob: bytes) -> str:
    if blob.startswith(JAVA_MAGIC):
        return "java_serialization"
    # Heuristic .NET detection
    for h in DOTNET_HINTS:
        if h in blob:
            return "dotnet_binaryformatter_likely"
    return "unknown"

def analyze(blob: bytes, sigs: Dict[str, Any]) -> Dict[str, Any]:
    fmt = detect_format(blob)
    findings = []

    if fmt == "java_serialization":
        findings.append(Finding(
            severity="high",
            title="Java native deserialization data detected",
            evidence="Stream starts with AC ED 00 05",
            recommendation="Avoid native Java deserialization of untrusted data. Use safe formats (JSON) + strict allowlists, or enforce signed/verified payloads."
        ))
    elif fmt == "dotnet_binaryformatter_likely":
        findings.append(Finding(
            severity="critical",
            title=".NET BinaryFormatter usage likely",
            evidence="BinaryFormatter-related markers found in content",
            recommendation="Do not use BinaryFormatter for untrusted data. Migrate to safe serializers and implement allowlists; follow Microsoft guidance to disable/replace BinaryFormatter."
        ))
    else:
        findings.append(Finding(
            severity="info",
            title="Unknown or non-native serialization format",
            evidence="No strong Java/.NET native serialization indicators found",
            recommendation="If this endpoint performs deserialization, validate content type, enforce strict schemas, and avoid unsafe serializers."
        ))

    # Optional signature checks (strings/bytes indicators)
    indicators = sigs.get("indicators", [])
    for ind in indicators:
        needle = ind.get("needle", "")
        if needle and needle.encode() in blob:
            findings.append(Finding(
                severity=ind.get("severity", "medium"),
                title=ind.get("title", "Suspicious indicator"),
                evidence=f"Matched indicator: {needle}",
                recommendation=ind.get("recommendation", "Review deserialization path and add allowlists / safe serialization.")
            ))

    risk = "low"
    if any(f.severity in ("high", "critical") for f in findings):
        risk = "high"
    elif any(f.severity == "medium" for f in findings):
        risk = "medium"

    return {
        "format": fmt,
        "risk": risk,
        "findings": [asdict(f) for f in findings],
        "notes_template": {
            "impact": "Potential remote code execution / auth bypass depending on reachable gadget chains and application context.",
            "where_to_check": [
                "Deserializer entry points (controllers, filters, message queues)",
                "Any allowlist / type binder logic",
                "Signed payload validation (HMAC/RSA) before deserialization",
            ],
            "recommended_controls": [
                "Replace unsafe serializers (BinaryFormatter/native Java)",
                "Strict allowlist / type restrictions",
                "Authenticate+integrity check before parse/deserialize",
                "Run deserialization in low-privilege sandbox if unavoidable"
            ]
        }
    }

@click.command()
@click.option("--input", "inp", required=True, help="Input data (raw string or base64)")
@click.option("--base64", "is_b64", is_flag=True, help="Treat input as base64")
@click.option("--signatures", default="rules/signatures.yml", show_default=True)
@click.option("--out", default="report.json", show_default=True)
def main(inp: str, is_b64: bool, signatures: str, out: str):
    sigs = load_signatures(signatures)
    blob = decode_input(inp, is_b64)
    report = analyze(blob, sigs)

    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    table = Table(title="Deserialization Risk Analyzer")
    table.add_column("Format", style="bold")
    table.add_column("Risk", style="bold")
    table.add_row(report["format"], report["risk"])
    console.print(table)

    console.print(f"[green]Saved:[/green] {out}")

if __name__ == "__main__":
    main()
