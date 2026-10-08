# NetScaler Defensive Checker — CVE-2026-88771 to CVE-2026-88778

**By Grupo Oruss | Division81 Defensive Security Research**

Read-only, offline Python 3 tool to **triage** Citrix NetScaler ADC / Gateway exposure under Citrix security bulletin [CTX697096](https://support.citrix.com/external/article?articleNumber=CTX697096). No network traffic, exploit payloads, DoS testing, authentication, or third-party telemetry. **Not a vulnerability exploitation detector or compromise assessment.**

## Use

Export a configuration you are authorized to inspect (`/nsconfig/ns.conf` or `show ns runningConfig` output). Obtain the installed firmware build from the appliance and optionally save the *text output* of `show ns tcpparam`. **Do not upload proprietary production configurations to GitHub, cloud services or issue trackers.**

```bash
python checker.py --config examples/sample.ns.conf --build 14.1-73.20 --tcp-params examples/tcpparam.txt --output report.json
```

No third-party dependencies. Windows, Linux and macOS compatible.

### Results

- `potentially_exposed`: supported affected build **and** a documented prerequisite appears to be present. It does **not** prove exploitable behavior.
- `fixed_build`: meets the advisory's fixed-build threshold, not a guarantee of no compromise.
- `precondition_not_observed`: the heuristic did not identify a prerequisite in the supplied snapshot; **not** a declaration of safety.
- `configuration_unknown`: critical supplemental configuration data are missing.
- `unknown_build`: no reliable edition/build classification was possible.

The JSON report deliberately contains counts, **not sensitive configuration lines**. Review source config locally.

## Checks

| CVE | CVSS v4 | Offline condition |
| --- | ---: | --- |
| CVE-2026-88771 | 9.5 | Version (all default configs affected on vulnerable builds) |
| CVE-2026-88772 | 9.5 | DTLS, including SSL VPN implicit defaults |
| CVE-2026-88773 | 9.3 | HTTP/SSL vServers |
| CVE-2026-88774 | 7.0 | HTTP URL expression heuristic; manually review bindings |
| CVE-2026-88775 | 8.8 | VPN or AAA vServers |
| CVE-2026-88776 | 8.8 | ORACLE LB vServer |
| CVE-2026-88777 | 8.8 | FTP/RTSP/DNS64/NAT64/LSN heuristics; verify feature bindings |
| CVE-2026-88778 | 8.8 | TCP vServer + Enhanced ISN Generation disabled from `show ns tcpparam` |

Fixed builds (per CTX697096): 14.1-73.37 / 13.1-64.23 for standard, 14.1-73.37 for FIPS, 13.1-37.279 for FIPS/NDcPP.

**Limitations:** This parser is heuristic and may miss context spread over multiple CLI lines, post-deployment defaults, indirect expressions and policy bindings; `show ns tcpparam` is needed for CVE-2026-88778. Missing entries in a partial exported configuration cannot rule out exposure. Build 13.0 and other unsupported/end-of-life versions are *unknown*, not safe. The checker does not confirm malicious exploitation. For internet-facing unpatched appliances, patch urgently and perform an independent incident/compromise assessment.

## Test

```bash
python -m unittest discover -s tests -v
```

## Responsible use

Only inspect configurations you own or have permission to assess. Never commit real exports or results containing internal details. License: MIT. This is an independent By Grupo Oruss | Division81 Defensive Security Research project, not affiliated with or endorsed by Citrix/NetScaler.

Sources: [Citrix CTX697096](https://support.citrix.com/external/article?articleNumber=CTX697096), [CISA notice](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42cc465).

## v1.1 — HTML executive report + JSON export

Generate both formats locally using the same read-only assessment:

```bash
python checker.py --config examples/sample.ns.conf --build 14.1-73.20 \
  --tcp-params examples/tcpparam.txt --json report.json --html report.html
```

On Windows PowerShell, run the command on one line or use the PowerShell backtick for continuation.
Open `report.html` locally in a browser; it is a standalone file with embedded CSS, no external scripts, assets or telemetry. `--output` remains a backward-compatible alias for `--json`. The HTML provides a KPI summary, findings for all eight CVEs, recommended actions and assessment caveats. It excludes raw configuration and matched lines; nevertheless, verify reports before sharing.

**Important:** Assessments on fixed builds are not evidence of absence of historic compromise. Consult the Citrix bulletin and CISA guidance for patching, indicators of compromise, and forensic preservation.
