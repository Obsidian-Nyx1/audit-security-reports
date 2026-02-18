#!/usr/bin/env python3
"""
Security report audit agent.

Profile-aware report auditor for offensive and purple-team assessments.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


DEFAULT_REPORT_EXTENSIONS = {
    ".txt",
    ".md",
    ".log",
    ".json",
    ".csv",
    ".xml",
    ".doc",
    ".docx",
    ".pdf",
}


PROFILE_MENU = [
    ("pentest_general", "Pentest Report (General)", "Internal or external pentest quality checks."),
    ("web_pentest", "Web Application Pentest", "Web/API offensive report checks (OWASP-heavy)."),
    ("internal_pentest", "Internal Infrastructure Pentest", "Lateral movement, AD, segmentation focus."),
    ("external_pentest", "External Infrastructure Pentest", "Perimeter exposure and exploitability focus."),
    ("red_team", "Red Team Operation Report", "Objective-driven adversary simulation outcomes."),
    ("purple_team", "Purple Team Exercise Report", "Detection improvement and ATT&CK mapping evidence."),
    ("adversary_emulation", "Adversary Emulation Report", "Threat-emulation chain and control validations."),
    ("phishing_assessment", "Phishing/Social Engineering Report", "Campaign metrics and control breakdown."),
    ("wireless_assessment", "Wireless Security Assessment", "Wi-Fi attack paths and wireless hardening gaps."),
    ("ad_assessment", "Active Directory Security Assessment", "Identity tiering, privilege paths, AD abuse risks."),
]

PROFILE_LOOKUP = {k: {"name": n, "description": d} for k, n, d in PROFILE_MENU}
PROFILE_BY_INDEX = {str(i + 1): PROFILE_MENU[i][0] for i in range(len(PROFILE_MENU))}

JOKES = [
    "Exploit succeeded on first try. Clearly a misconfiguration, not luck.",
    "No zero-days were harmed while generating this report.",
    "If it says 'critical', it is not a motivational suggestion.",
    "Today\'s payload is: better evidence quality.",
    "We came for shells, stayed for remediation notes.",
    "Attack path found. Coffee path still unresolved.",
    "Privilege escalation is temporary, audit artifacts are forever.",
    "Another day, another exposed management interface.",
    "The only acceptable false negative is none.",
    "Your SOC called; it wants cleaner indicators and fewer surprises.",
]

CONSOLE_TAGLINES = [
    "Turning raw findings into executive-grade evidence.",
    "Signal over noise, evidence over guesswork.",
    "Built for operators who also care about documentation quality.",
    "Every control gets context, every gap gets clarity.",
]

PROFILE_RECOMMENDATIONS = {
    "pentest_general": [
        "Ensure every finding has reproducible steps, impact, and business risk.",
        "Use CVSS plus environmental context for prioritization.",
    ],
    "web_pentest": [
        "Map findings to OWASP categories and affected endpoints.",
        "Provide secure coding and validation fixes per finding class.",
    ],
    "internal_pentest": [
        "Document lateral movement chain with host-to-host evidence.",
        "Prioritize identity hardening and segmentation remediation.",
    ],
    "external_pentest": [
        "Prioritize internet-exposed attack paths and boundary controls.",
        "Retest externally reachable high-risk assets after fixes.",
    ],
    "red_team": [
        "Tie objectives to mission impact and control bypass narrative.",
        "Capture detection failures by phase and recommend telemetry gaps.",
    ],
    "purple_team": [
        "Maintain ATT&CK technique-to-detection matrix and tuning history.",
        "Include before/after detection performance metrics.",
    ],
    "adversary_emulation": [
        "Reference emulated threat playbook and sequence fidelity.",
        "Validate prevention, detection, and response outcomes per stage.",
    ],
    "phishing_assessment": [
        "Include campaign stats, click/submit rates, and user cohorts.",
        "Pair training recommendations with control enhancements.",
    ],
    "wireless_assessment": [
        "Document encryption/auth weaknesses and practical compromise paths.",
        "Include rogue AP and client isolation control checks.",
    ],
    "ad_assessment": [
        "Map privilege escalation paths and toxic permission chains.",
        "Prioritize tiered admin model and credential hygiene controls.",
    ],
}


@dataclass
class ControlResult:
    control_id: str
    title: str
    frameworks: List[str]
    matched_keywords: List[str]
    missing_keywords: List[str]
    evidence_files: List[str]
    status: str


def banner() -> None:
    art = [
        "  ,.:[]:.,----------------------------------------------------,.:[]:.,",
        "  [ audit-forge ]    CIPHER TRACE WORKBENCH    [ evidence-lab ]",
        "  `:.,[]:.'----------------------------------------------------`:.,[]:.'",
    ]
    for line in art:
        print(colorize(line, "cyan"))
    print(colorize(f"  [*] {random.choice(CONSOLE_TAGLINES)}", "green"))
    print(colorize(f"  [*] joke> {random.choice(JOKES)}", "yellow"))
    print()


def usage_hint() -> None:
    print(colorize("[.] Usage examples", "blue"))
    print(colorize('  [1] ./audit_agent.py "example.doc" --output-format pdf', "white"))
    print(colorize('  [2] ./audit_agent.py "example.pdf" --output-format doc', "white"))
    print(colorize('  [3] ./audit_agent.py "/full/path/to/example.xml" --output-format pdf', "white"))
    print()


def print_profile_menu() -> None:
    print(colorize("[.] Select report type", "magenta"))
    for i, (_, name, desc) in enumerate(PROFILE_MENU, start=1):
        idx = colorize(f"[{i:>2}]", "cyan")
        print(f"  {idx} {colorize(name, 'green')} :: {desc}")
    print()


def choose_profile_interactive() -> str:
    while True:
        selected = input(colorize("select profile number (1-10) [1]: ", "yellow")).strip() or "1"
        if selected in PROFILE_BY_INDEX:
            return PROFILE_BY_INDEX[selected]
        print(colorize("[!] Invalid selection. Choose 1-10.", "red"))


def load_catalog(path: Path) -> List[Dict]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    controls = payload.get("controls", [])
    if not controls:
        raise ValueError(f"No controls found in catalog: {path}")
    return controls


def filter_controls_by_profile(controls: List[Dict], profile: str) -> List[Dict]:
    filtered = []
    for control in controls:
        profiles = control.get("profiles", ["all"])
        if "all" in profiles or profile in profiles:
            filtered.append(control)
    return filtered


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract_from_xml(path: Path) -> str:
    try:
        root = ET.parse(path).getroot()
        text = " ".join(t.strip() for t in root.itertext() if t and t.strip())
        return text
    except ET.ParseError:
        return read_text_file(path)


def extract_from_docx(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            xml_blob = archive.read("word/document.xml").decode("utf-8", errors="ignore")
        root = ET.fromstring(xml_blob)
        text = " ".join(t.strip() for t in root.itertext() if t and t.strip())
        return text
    except Exception:
        return ""


def extract_from_doc(path: Path) -> str:
    try:
        result = subprocess.run(["antiword", str(path)], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except FileNotFoundError:
        pass

    try:
        raw = path.read_bytes()
        text = raw.decode("latin-1", errors="ignore")
        clean = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", " ", text)
        return re.sub(r"\s+", " ", clean)
    except OSError:
        return ""


def extract_from_pdf(path: Path) -> str:
    try:
        result = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except FileNotFoundError:
        pass

    try:
        blob = path.read_bytes()
        candidates = re.findall(rb"[A-Za-z0-9 ,.:;_\-()/]{6,}", blob)
        return "\n".join(x.decode("latin-1", errors="ignore") for x in candidates)
    except OSError:
        return ""


def read_report(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md", ".log", ".json", ".csv"}:
        return read_text_file(path)
    if suffix == ".xml":
        return extract_from_xml(path)
    if suffix == ".docx":
        return extract_from_docx(path)
    if suffix == ".doc":
        return extract_from_doc(path)
    if suffix == ".pdf":
        return extract_from_pdf(path)
    return ""


def collect_reports_from_dir(report_dir: Path, exts: set[str]) -> Dict[str, str]:
    files = {}
    for p in sorted(report_dir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        text = read_report(p)
        if text.strip():
            files[str(p)] = text
    return files


def collect_reports_from_paths(paths: List[Path], exts: set[str]) -> Dict[str, str]:
    files = {}
    for p in paths:
        if not p.exists() or not p.is_file() or p.suffix.lower() not in exts:
            continue
        text = read_report(p)
        if text.strip():
            files[str(p)] = text
    return files


def parse_file_list(raw: str) -> List[Path]:
    return [Path(x.strip()) for x in raw.split(",") if x.strip()]


def find_keyword_hits(text: str, keywords: List[str]) -> List[str]:
    hits = []
    lowered = text.lower()
    for kw in keywords:
        if re.search(rf"\b{re.escape(kw.lower())}\b", lowered):
            hits.append(kw)
    return hits


def evaluate_control(control: Dict, report_texts: Dict[str, str]) -> ControlResult:
    required_keywords = control.get("required_keywords", [])
    file_hits: Dict[str, List[str]] = {}

    for file_path, content in report_texts.items():
        hits = find_keyword_hits(content, required_keywords)
        if hits:
            file_hits[file_path] = hits

    matched = sorted({kw for kws in file_hits.values() for kw in kws})
    missing = sorted(set(required_keywords) - set(matched))
    coverage = len(matched) / len(required_keywords) if required_keywords else 0.0

    if coverage >= 0.8:
        status = "PASS"
    elif coverage >= 0.4:
        status = "PARTIAL"
    else:
        status = "FAIL"

    return ControlResult(
        control_id=control["id"],
        title=control["title"],
        frameworks=control.get("frameworks", []),
        matched_keywords=matched,
        missing_keywords=missing,
        evidence_files=sorted(file_hits.keys()),
        status=status,
    )


def evaluate_controls(controls: List[Dict], report_texts: Dict[str, str]) -> List[ControlResult]:
    return [evaluate_control(control, report_texts) for control in controls]


def summarize(results: List[ControlResult]) -> Tuple[int, int, int]:
    passed = sum(1 for r in results if r.status == "PASS")
    partial = sum(1 for r in results if r.status == "PARTIAL")
    failed = sum(1 for r in results if r.status == "FAIL")
    return passed, partial, failed


def write_json(results: List[ControlResult], out_path: Path, metadata: Dict[str, object]) -> None:
    payload = {
        "metadata": metadata,
        "summary": {},
        "results": [
            {
                "control_id": r.control_id,
                "title": r.title,
                "frameworks": r.frameworks,
                "status": r.status,
                "matched_keywords": r.matched_keywords,
                "missing_keywords": r.missing_keywords,
                "evidence_files": r.evidence_files,
            }
            for r in results
        ],
    }
    p, q, f = summarize(results)
    payload["summary"] = {"pass": p, "partial": q, "fail": f, "total": len(results)}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def score_label(results: List[ControlResult]) -> str:
    p, q, f = summarize(results)
    total = max(1, p + q + f)
    weighted = ((p * 1.0) + (q * 0.5)) / total
    if weighted >= 0.85:
        return "Low Risk"
    if weighted >= 0.65:
        return "Moderate Risk"
    return "High Risk"


def write_markdown(results: List[ControlResult], out_path: Path, metadata: Dict[str, object]) -> str:
    p, q, f = summarize(results)
    risk = score_label(results)
    profile_key = str(metadata.get("profile_key", "pentest_general"))
    profile_name = PROFILE_LOOKUP.get(profile_key, {}).get("name", profile_key)
    recs = PROFILE_RECOMMENDATIONS.get(profile_key, ["Prioritize FAIL controls then PARTIAL controls."])

    lines = [
        "# Security Audit Report",
        "",
        "## Executive Summary",
        f"- Client/Project: {metadata.get('project_name', 'Unnamed Engagement')}",
        f"- Assessment date: {metadata.get('assessed_at', '')}",
        f"- Report profile: {profile_name}",
        f"- Overall posture: {risk}",
        f"- Controls tested: {len(results)}",
        f"- PASS: {p}, PARTIAL: {q}, FAIL: {f}",
        "",
        "## Scope and Inputs",
        "- Input files:",
    ]

    for fpath in metadata.get("input_files", []):
        lines.append(f"  - {Path(str(fpath)).name}")

    lines.extend(
        [
            "",
            "## Methodology",
            "- Evidence extraction from report artifacts (.txt/.md/.log/.json/.csv/.xml/.doc/.docx/.pdf).",
            "- Profile-aware control filtering for offensive/purple assessment types.",
            "- Status logic: PASS (>=80%), PARTIAL (40-79%), FAIL (<40%).",
            "",
            "## Control Summary",
            "",
            "| Control | Status | Frameworks | Evidence Files | Missing Keywords |",
            "|---|---|---|---|---|",
        ]
    )

    for r in results:
        frameworks = ", ".join(r.frameworks) if r.frameworks else "n/a"
        files = "<br>".join(Path(x).name for x in r.evidence_files) if r.evidence_files else "none"
        missing = ", ".join(r.missing_keywords) if r.missing_keywords else "none"
        lines.append(f"| {r.control_id} {r.title} | {r.status} | {frameworks} | {files} | {missing} |")

    lines.extend(["", "## Recommendations"])
    for rec in recs:
        lines.append(f"- {rec}")

    lines.extend(
        [
            "",
            "## Limitations",
            "- This report is evidence-based and depends on provided document quality.",
            "- Point-in-time assessment; environment changes may alter risk status.",
        ]
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    markdown = "\n".join(lines) + "\n"
    out_path.write_text(markdown, encoding="utf-8")
    return markdown


def markdown_to_html(markdown_text: str, title: str) -> str:
    def esc(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    blocks: List[str] = []
    in_list = False
    in_table = False
    table_header_written = False

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            blocks.append("</ul>")
            in_list = False

    def close_table() -> None:
        nonlocal in_table, table_header_written
        if in_table:
            if table_header_written:
                blocks.append("</tbody>")
            blocks.append("</table>")
            in_table = False
            table_header_written = False

    for raw in markdown_text.splitlines():
        line = raw.rstrip()

        if not line.strip():
            close_list()
            close_table()
            continue

        if line.startswith("# "):
            close_list()
            close_table()
            blocks.append(f"<h1>{esc(line[2:].strip())}</h1>")
            continue

        if line.startswith("## "):
            close_list()
            close_table()
            blocks.append(f"<h2>{esc(line[3:].strip())}</h2>")
            continue

        if line.startswith("- "):
            close_table()
            if not in_list:
                blocks.append("<ul>")
                in_list = True
            blocks.append(f"<li>{esc(line[2:].strip())}</li>")
            continue

        if line.startswith("|") and line.endswith("|"):
            close_list()
            cells = [esc(c.strip()) for c in line.strip("|").split("|")]
            if all(set(c) <= {"-"} and c for c in cells):
                continue
            if not in_table:
                blocks.append("<table>")
                in_table = True
                table_header_written = False
            if not table_header_written:
                blocks.append("<thead><tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr></thead><tbody>")
                table_header_written = True
            else:
                blocks.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            continue

        close_list()
        close_table()
        blocks.append(f"<p>{esc(line)}</p>")

    close_list()
    close_table()
    body = "\n".join(blocks)
    return (
        "<html><head><meta charset='utf-8'><title>"
        + esc(title)
        + "</title><style>"
        "body{font-family:'Times New Roman',Times,serif;font-size:12pt;line-height:1.45;margin:1in;color:#111;}"
        "h1{font-size:22pt;margin:0 0 14pt 0;color:#0e2439;border-bottom:1px solid #b8c4cf;padding-bottom:6pt;}"
        "h2{font-size:15pt;margin:18pt 0 8pt 0;color:#123a5f;}"
        "p{margin:0 0 8pt 0;} ul{margin:0 0 10pt 18pt;padding:0;} li{margin:0 0 4pt 0;}"
        "table{width:100%;border-collapse:collapse;margin:8pt 0 12pt 0;}"
        "th,td{border:1px solid #9aa7b3;padding:6pt;vertical-align:top;}"
        "th{background:#eef2f6;text-align:left;font-weight:bold;}"
        "</style></head><body>"
        + body
        + "</body></html>"
    )


def write_doc_report(markdown_text: str, out_path: Path, title: str) -> None:
    html = markdown_to_html(markdown_text, title)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")


def _escape_pdf_text(line: str) -> str:
    return line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _line_wrap(text: str, width: int = 95) -> List[str]:
    pieces: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            pieces.append("")
            continue
        while len(line) > width:
            split_at = line.rfind(" ", 0, width)
            split_at = split_at if split_at > 0 else width
            pieces.append(line[:split_at].rstrip())
            line = line[split_at:].lstrip()
        pieces.append(line)
    return pieces


def write_pdf_report(text: str, out_path: Path) -> None:
    lines = _line_wrap(text, width=95)
    lines_per_page = 48
    page_chunks = [lines[i : i + lines_per_page] for i in range(0, len(lines), lines_per_page)] or [["Security Audit Report"]]

    objects: List[bytes] = []

    def add_obj(content: bytes) -> int:
        objects.append(content)
        return len(objects)

    add_obj(b"<< /Type /Catalog /Pages 2 0 R >>")
    add_obj(b"<< /Type /Pages /Kids [] /Count 0 >>")
    font_id = add_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids: List[int] = []
    for chunk in page_chunks:
        commands = [b"BT", b"/F1 10 Tf", b"50 760 Td", b"14 TL"]
        for line in chunk:
            if line:
                commands.append(f"({_escape_pdf_text(line)}) Tj".encode("latin-1", errors="ignore"))
            commands.append(b"T*")
        commands.append(b"ET")
        stream = b"\n".join(commands) + b"\n"
        content_id = add_obj(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream")
        page_obj = (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 " + str(font_id).encode("ascii") + b" 0 R >> >> "
            b"/Contents " + str(content_id).encode("ascii") + b" 0 R >>"
        )
        page_ids.append(add_obj(page_obj))

    kids = b" ".join(f"{pid} 0 R".encode("ascii") for pid in page_ids)
    objects[1] = b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(page_ids)).encode("ascii") + b" >>"

    xref_offsets = [0]
    output = [b"%PDF-1.4\n"]
    current_offset = len(output[0])

    for idx, obj in enumerate(objects, start=1):
        chunk = f"{idx} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
        xref_offsets.append(current_offset)
        output.append(chunk)
        current_offset += len(chunk)

    xref_start = current_offset
    xref = [f"xref\n0 {len(objects) + 1}\n".encode("ascii"), b"0000000000 65535 f \n"]
    for off in xref_offsets[1:]:
        xref.append(f"{off:010d} 00000 n \n".encode("ascii"))

    trailer = (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref_start).encode("ascii")
        + b"\n%%EOF\n"
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as handle:
        for part in output + xref:
            handle.write(part)
        handle.write(trailer)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Profile-aware security report auditor.")
    parser.add_argument(
        "input",
        nargs="*",
        help="Report file path(s) or comma-separated list (e.g., example.pdf or a.pdf,b.xml).",
    )
    parser.add_argument("--reports-dir", default="reports", help="Directory containing report files when no input is provided.")
    parser.add_argument("--catalog", default="controls/security_controls_catalog.json", help="Path to control catalog JSON.")
    parser.add_argument("--output-dir", default="output", help="Directory for generated outputs.")
    parser.add_argument("--output-format", choices=["doc", "pdf"], default="pdf", help="Final report format.")
    parser.add_argument("--output-name", default="security_audit_report", help="Final report filename without extension.")
    parser.add_argument("--project-name", default="", help="Project/client name for report cover section.")
    parser.add_argument("--profile", choices=[x[0] for x in PROFILE_MENU], default="pentest_general", help="Report profile for targeted controls.")
    parser.add_argument("--interactive", action="store_true", help="Prompt for files and output format interactively.")
    parser.add_argument("--list-profiles", action="store_true", help="List available profiles and exit.")
    return parser.parse_args()


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.getenv("TERM", "").lower() != "dumb"


USE_COLOR = _supports_color()

ANSI_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
}


def colorize(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    code = ANSI_COLORS.get(color, "")
    reset = ANSI_COLORS["reset"] if code else ""
    return f"{code}{text}{reset}"


def animate_console(message: str, cycles: int = 14, delay: float = 0.06) -> None:
    if not sys.stdout.isatty():
        print(f"{message} ...")
        return

    frames = [
        "[.:,]",
        "{:..}",
        "(.,:)",
        "<..,>",
        "[,::]",
        "{.,.}",
        "(::,)",
        "<,.:>",
    ]
    for i in range(cycles):
        frame = frames[i % len(frames)]
        line = f"\r{colorize(frame, 'cyan')} {colorize(message, 'white')}"
        print(line, end="", flush=True)
        time.sleep(delay)
    print(f"\r{colorize('[ ok ]', 'green')} {message}{' ' * 24}")


def list_profiles() -> None:
    print_profile_menu()


def interactive_inputs(args: argparse.Namespace) -> argparse.Namespace:
    banner()
    animate_console("Initializing modules")
    animate_console("Loading control intelligence")
    usage_hint()
    print_profile_menu()
    args.profile = choose_profile_interactive()

    print(colorize("[.] Enter report file/path (single file or comma-separated list):", "blue"))
    raw_files = input(colorize("  > ", "cyan")).strip()
    args.input = [raw_files] if raw_files else []

    fmt = input(colorize("preferred output format (doc/pdf) [pdf]: ", "yellow")).strip().lower()
    if fmt in {"doc", "pdf"}:
        args.output_format = fmt

    pname = input(colorize("project name [Security Audit Engagement]: ", "yellow")).strip()
    args.project_name = pname or "Security Audit Engagement"

    oname = input(colorize("output filename [security_audit_report]: ", "yellow")).strip()
    if oname:
        args.output_name = oname
    return args


def resolve_reports(args: argparse.Namespace) -> Dict[str, str]:
    paths: List[Path] = []
    if args.input:
        for item in args.input:
            paths.extend(parse_file_list(item))
    if paths:
        return collect_reports_from_paths(paths, DEFAULT_REPORT_EXTENSIONS)
    return collect_reports_from_dir(Path(args.reports_dir), DEFAULT_REPORT_EXTENSIONS)


def main() -> None:
    args = parse_args()

    if args.list_profiles:
        list_profiles()
        return

    if args.interactive or len(sys.argv) == 1:
        args = interactive_inputs(args)

    animate_console("Parsing report inputs")
    controls = filter_controls_by_profile(load_catalog(Path(args.catalog)), args.profile)
    reports = resolve_reports(args)
    if not reports:
        raise SystemExit("No supported report files found. Provide .txt/.md/.log/.json/.csv/.xml/.doc/.docx/.pdf files.")
    if not controls:
        raise SystemExit(f"No controls mapped for selected profile '{args.profile}'.")

    animate_console("Evaluating controls")
    results = evaluate_controls(controls, reports)
    profile_name = PROFILE_LOOKUP.get(args.profile, {}).get("name", args.profile)
    metadata: Dict[str, object] = {
        "project_name": args.project_name or "Security Audit Engagement",
        "assessed_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "input_files": sorted(reports.keys()),
        "profile_key": args.profile,
        "profile_name": profile_name,
    }

    output_dir = Path(args.output_dir)
    json_out = output_dir / "control_assessment.json"
    md_out = output_dir / "control_assessment.md"
    write_json(results, json_out, metadata)
    markdown_report = write_markdown(results, md_out, metadata)

    final_report = output_dir / f"{args.output_name}.{args.output_format}"
    if args.output_format == "doc":
        animate_console("Rendering DOC report")
        write_doc_report(markdown_report, final_report, args.output_name)
    else:
        animate_console("Rendering PDF report")
        write_pdf_report(markdown_report, final_report)

    p, q, f = summarize(results)
    pass_label = colorize(f"PASS={p}", "green")
    partial_label = colorize(f"PARTIAL={q}", "yellow")
    fail_label = colorize(f"FAIL={f}", "red")
    print(colorize(f"[+] Assessment complete. Profile={profile_name} {pass_label} {partial_label} {fail_label}", "white"))
    print(colorize(f"  [>] JSON: {json_out}", "cyan"))
    print(colorize(f"  [>] Markdown: {md_out}", "cyan"))
    print(colorize(f"  [>] Final report: {final_report}", "cyan"))


if __name__ == "__main__":
    main()
