"""
Builds the approval email as a MIME multipart message (HTML + plain text).
No external dependencies beyond the standard library email module.
"""
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

from models.report import DailyReport


def build_approval_email(report: DailyReport) -> MIMEMultipart:
    """Return a MIME message ready to be base64-encoded and sent via Gmail API."""
    date_label = datetime.strptime(report.report_id, "%Y-%m-%d").strftime("%B %d, %Y")
    subject = f"[CyberIntel] Approval Required — Daily Threat Report: {date_label}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = ""   # filled in by sender.py
    msg["To"] = ""     # filled in by sender.py

    msg.attach(MIMEText(_build_plain(report, date_label), "plain", "utf-8"))
    msg.attach(MIMEText(_build_html(report, date_label), "html", "utf-8"))
    return msg


# ── Plain text ────────────────────────────────────────────────────────────────

def _build_plain(report: DailyReport, date_label: str) -> str:
    total = len(report.vulnerabilities) + len(report.threat_events)
    lines = [
        f"CYBERINTEL — DAILY THREAT REPORT: {date_label}",
        "=" * 60,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 60,
        _wrap(report.executive_summary),
        "",
        "DETAILED SUMMARY",
        "-" * 60,
        _wrap(report.detailed_summary),
        "",
        "THREAT STATISTICS (Last 48 Hours)",
        "-" * 60,
        f"  Critical CVEs      : {report.critical_cve_count}",
        f"  Actively Exploited : {report.kev_count}",
        f"  Data Breaches      : {report.breach_count}",
        f"  Cyber Attacks      : {report.attack_count}",
        f"  Total Items        : {total}",
        "",
        "TOP CRITICAL CVEs",
        "-" * 60,
        _top_cves_plain(report),
        "",
        "=" * 60,
        "HOW TO RESPOND",
        "=" * 60,
        "",
        "  Reply APPROVE   → Publish the Detailed Summary to LinkedIn",
        "  Reply REJECT    → Skip publishing for today",
        "  Attach .txt     → Publish your edited content instead",
        "",
        "Nothing will be published without your explicit approval.",
        "",
        f"Report ID : {report.report_id}",
        f"Generated : {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    return "\n".join(lines)


def _top_cves_plain(report: DailyReport) -> str:
    from models.vulnerability import Severity
    critical = [v for v in report.vulnerabilities if v.severity == Severity.CRITICAL]
    top = sorted(critical, key=lambda v: v.cvss.base_score if v.cvss else 0, reverse=True)[:5]
    if not top:
        return "  No critical CVEs in this window."
    rows = []
    for v in top:
        score = f"CVSS {v.cvss.base_score:.1f}" if v.cvss else "Score N/A"
        kev = " [ACTIVELY EXPLOITED]" if v.is_known_exploited else ""
        rows.append(f"  • {v.cve_id} ({score}){kev}")
        if v.description:
            rows.append(f"    {_wrap(v.description[:120], width=76, indent='    ')}")
    return "\n".join(rows)


def _wrap(text: str, width: int = 76, indent: str = "") -> str:
    if not text:
        return ""
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


# ── HTML ──────────────────────────────────────────────────────────────────────

def _build_html(report: DailyReport, date_label: str) -> str:
    total = len(report.vulnerabilities) + len(report.threat_events)
    top_cves_html = _top_cves_html(report)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
         font-size: 14px; color: #1a1a1a; background: #f5f5f5; margin: 0; padding: 20px; }}
  .card {{ background: #ffffff; border-radius: 8px; padding: 32px;
           max-width: 680px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,.08); }}
  .header {{ border-bottom: 3px solid #c0392b; padding-bottom: 16px; margin-bottom: 24px; }}
  .header h1 {{ margin: 0; font-size: 20px; color: #c0392b; }}
  .header p {{ margin: 4px 0 0; color: #666; font-size: 13px; }}
  h2 {{ font-size: 13px; text-transform: uppercase; letter-spacing: .08em;
        color: #555; margin: 24px 0 8px; border-bottom: 1px solid #eee; padding-bottom: 6px; }}
  .summary {{ background: #f9f9f9; border-left: 4px solid #c0392b;
              padding: 14px 18px; border-radius: 0 6px 6px 0; font-size: 14px;
              line-height: 1.6; margin-bottom: 8px; }}
  .stats {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 12px 0; }}
  .stat {{ background: #f9f9f9; border-radius: 6px; padding: 12px 16px; }}
  .stat .num {{ font-size: 28px; font-weight: 700; color: #c0392b; line-height: 1; }}
  .stat .lbl {{ font-size: 11px; color: #777; text-transform: uppercase; margin-top: 2px; }}
  .stat.warn .num {{ color: #e67e22; }}
  table.cves {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }}
  table.cves th {{ background: #f0f0f0; text-align: left; padding: 8px 10px;
                   font-weight: 600; font-size: 11px; text-transform: uppercase;
                   color: #555; }}
  table.cves td {{ padding: 8px 10px; border-top: 1px solid #f0f0f0; vertical-align: top; }}
  table.cves tr:hover td {{ background: #fafafa; }}
  .kev-badge {{ background: #c0392b; color: #fff; font-size: 10px; font-weight: 700;
                padding: 2px 6px; border-radius: 3px; text-transform: uppercase; }}
  .approval-box {{ background: #1a1a2e; color: #e0e0e0; border-radius: 8px;
                   padding: 24px; margin-top: 28px; }}
  .approval-box h2 {{ color: #aaa; border-color: #333; }}
  .approval-box p {{ margin: 4px 0; font-size: 13px; line-height: 1.7; }}
  .approval-box code {{ background: #0f3460; color: #e0e0e0; padding: 2px 8px;
                        border-radius: 3px; font-family: monospace; }}
  .footer {{ text-align: center; color: #aaa; font-size: 11px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>Daily Threat Report</h1>
    <p>{date_label} &nbsp;·&nbsp; Last 48 hours &nbsp;·&nbsp; Report ID: {report.report_id}</p>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary">{report.executive_summary}</div>

  <h2>Detailed Summary</h2>
  <div class="summary">{report.detailed_summary}</div>

  <h2>Threat Statistics</h2>
  <div class="stats">
    <div class="stat">
      <div class="num">{report.critical_cve_count}</div>
      <div class="lbl">Critical CVEs</div>
    </div>
    <div class="stat">
      <div class="num">{report.kev_count}</div>
      <div class="lbl">Actively Exploited</div>
    </div>
    <div class="stat warn">
      <div class="num">{report.breach_count}</div>
      <div class="lbl">Data Breaches</div>
    </div>
    <div class="stat warn">
      <div class="num">{report.attack_count}</div>
      <div class="lbl">Cyber Attacks</div>
    </div>
  </div>
  <p style="color:#888;font-size:12px;margin:4px 0 0">{total} total items collected</p>

  <h2>Top Critical CVEs</h2>
  {top_cves_html}

  <div class="approval-box">
    <h2>How to Respond</h2>
    <p><code>APPROVE</code> &nbsp;→&nbsp; Publish the Detailed Summary to LinkedIn</p>
    <p><code>REJECT</code> &nbsp;→&nbsp; Skip publishing for today</p>
    <p>Attach a <code>.txt</code> file &nbsp;→&nbsp; Publish your edited content instead</p>
    <p style="margin-top:14px;color:#888;font-size:12px;">
      Nothing will be published without your explicit approval.<br>
      Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}
    </p>
  </div>
</div>
<div class="footer">CyberIntel Automation &nbsp;·&nbsp; {report.report_id}</div>
</body>
</html>"""


def _top_cves_html(report: DailyReport) -> str:
    from models.vulnerability import Severity
    critical = [v for v in report.vulnerabilities if v.severity == Severity.CRITICAL]
    top = sorted(critical, key=lambda v: v.cvss.base_score if v.cvss else 0, reverse=True)[:5]

    if not top:
        return '<p style="color:#888;font-size:13px;">No critical CVEs in this window.</p>'

    rows = ""
    for v in top:
        score = f"{v.cvss.base_score:.1f}" if v.cvss else "—"
        kev = '<span class="kev-badge">Exploited</span>' if v.is_known_exploited else ""
        desc = (v.description[:140] + "…") if len(v.description) > 140 else v.description
        rows += f"""
        <tr>
          <td><strong>{v.cve_id}</strong> {kev}<br>
              <span style="color:#888;font-size:12px;">{desc}</span></td>
          <td style="white-space:nowrap;color:#c0392b;font-weight:700">{score}</td>
        </tr>"""

    return f"""
    <table class="cves">
      <thead><tr><th>CVE</th><th>CVSS</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""
