#!/usr/bin/env python3
"""By Grupo Oruss | Division81 Defensive Security Research"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ADVISORY = 'https://support.citrix.com/external/article?articleNumber=CTX697096'
SCORES = {'88771':9.5,'88772':9.5,'88773':9.3,'88774':7.0,'88775':8.8,'88776':8.8,'88777':8.8,'88778':8.8}
FIXED = {('standard','14.1'):(73,37),('standard','13.1'):(64,23),('fips','14.1'):(73,37),('fips','13.1'):(37,279),('ndcpp','13.1'):(37,279)}
TCP_TYPES = set('HTTP SSL SSL_BRIDGE TCP SSL_TCP FTP NNTP RTSP RDP DNS_TCP DOT SIP_TCP SIP_SSL DIAMETER SSL_DIAMETER MYSQL MSSQL ORACLE SMPP MQTT MQTT_TLS MONGO MONGO_TLS PROXY SSL_PROXY USER_TCP USER_SSL_TCP'.split())

def build_check(raw, edition):
    if not raw:
        return 'unknown', 'No appliance build supplied'
    match = re.fullmatch(r'\s*(13\.1|14\.1)[.-](\d+)\.(\d+)\s*',raw)
    if not match:
        return 'unknown', 'Unrecognized or unsupported build format; no safe classification'
    branch, major, minor = match.groups()
    fixed = FIXED.get((edition,branch))
    if not fixed:
        return 'unknown', f'Edition/branch {edition}/{branch} not covered by fixed-build matrix'
    if (int(major),int(minor)) < fixed:
        return 'affected_build', f'Build below fixed {branch}-{fixed[0]}.{fixed[1]}'
    return 'fixed_build', f'Build at or above fixed {branch}-{fixed[0]}.{fixed[1]}'

def evaluate(config, build='', edition='standard', tcpparam=''):
    lines = [l.strip() for l in config.splitlines() if l.strip() and not l.lstrip().startswith('#')]
    entries = [l for l in lines if re.match(r'^add\s+',l,re.I)]
    def matching(pattern): return [l for l in lines if re.search(pattern,l,re.I)]
    def adds(kind): return [l for l in entries if re.match(r'^add\s+'+kind+r'\s+',l,re.I)]
    vs = [l for l in entries if re.match(r'^add\s+(?:lb|cs|vpn|authentication)\s+vserver\s+',l,re.I)]
    def vs_type(line):
        m = re.match(r'^add\s+(?:lb|cs|vpn|authentication)\s+vserver\s+\S+\s+(\S+)',line,re.I)
        return m.group(1).upper() if m else ''
    vpn = [l for l in vs if re.match(r'^add\s+vpn\s+vserver',l,re.I)]
    dtls_vpn = [l for l in vpn if vs_type(l)=='DTLS' or (vs_type(l)=='SSL' and not re.search(r'-dtls\s+OFF\b',l,re.I))]
    dtls_other = [l for l in vs if vs_type(l)=='DTLS']
    http = [l for l in vs if vs_type(l) in ('HTTP','SSL')]
    url_expr = matching(r'HTTP\.REQ\.URL|HTTP\.RES\.URL|REQ\.HTTP\.URL|HTTP\.REQ\.FULL_HEADER.*URL')
    gateway = vpn + [l for l in vs if re.match(r'^add\s+authentication\s+vserver',l,re.I)]
    oracle = [l for l in vs if re.match(r'^add\s+lb\s+vserver',l,re.I) and vs_type(l)=='ORACLE']
    ftp = matching(r'^add\s+(?:lb|cs)\s+vserver\s+\S+\s+FTP\b|^add\s+service\s+\S+\s+\S+\s+FTP\b|^add\s+lb\s+monitor\s+\S+\s+FTP(?:-EXTENDED)?\b')
    lsn = matching(r'^add\s+lsn\s+group\s+')
    lsn_at_risk = []
    for line in lsn:
        name = re.search(r'^add\s+lsn\s+group\s+(\S+)',line,re.I).group(1)
        overrides = [l for l in lines if re.search(r'^set\s+lsn\s+group\s+'+re.escape(name)+r'(?:\s|$)',l,re.I)]
        if not any(re.search(r'-ftp\s+DISABLED\b',l,re.I) for l in overrides): lsn_at_risk.append(line)
    rtsp = matching(r'^set\s+lsn\s+group\s+\S+.*-rtspalg\s+ENABLED\b')
    dns64 = matching(r'^add\s+lb\s+vserver\s+\S+\s+DNS\b.*-dns64\s+ENABLED\b')
    dns64_policy = matching(r'^add\s+dns\s+policy64\b')
    nat64 = matching(r'^add\s+nat64\b')
    nonhttp = ftp + lsn_at_risk + rtsp + dns64 + dns64_policy + nat64
    tcp_vservers = [l for l in vs if vs_type(l) in TCP_TYPES]
    isn_disabled = bool(re.search(r'Enhanced ISN Generation\s*:\s*DISABLED\b',tcpparam,re.I))
    isn_enabled = bool(re.search(r'Enhanced ISN Generation\s*:\s*ENABLED\b',tcpparam,re.I))
    checks = {
        '88771': (True, 'No additional feature prerequisite'),
        '88772': (bool(dtls_vpn or dtls_other), 'DTLS enabled or default-on SSL VPN detected'),
        '88773': (bool(http), 'HTTP/SSL virtual server detected'),
        '88774': (bool(url_expr), 'HTTP URL expression detected (heuristic; manual policy review required)'),
        '88775': (bool(gateway), 'VPN or authentication virtual server detected'),
        '88776': (bool(oracle), 'ORACLE load-balancing virtual server detected'),
        '88777': (bool(nonhttp), 'Potential non-HTTP L7 or CGNAT/NAT64 precondition detected; review bindings'),
        '88778': (bool(tcp_vservers) and isn_disabled, 'TCP virtual server and Enhanced ISN disabled')
    }
    evidence = {'88771':[], '88772':dtls_vpn+dtls_other, '88773':http, '88774':url_expr,'88775':gateway,'88776':oracle,'88777':nonhttp,'88778':tcp_vservers}
    bs, detail = build_check(build,edition)
    results=[]
    for suffix,(present,note) in checks.items():
        if bs == 'fixed_build': state='fixed_build'
        elif bs == 'unknown': state='unknown_build'
        elif suffix == '88778' and not tcpparam: state='configuration_unknown'
        elif suffix == '88778' and tcp_vservers and not (isn_disabled or isn_enabled): state='configuration_unknown'
        elif suffix == '88778' and isn_enabled: state='precondition_not_observed'
        elif present: state='potentially_exposed'
        elif suffix == '88771': state='potentially_exposed'
        else: state='precondition_not_observed'
        results.append({'cve':'CVE-2026-'+suffix,'cvss_v4':SCORES[suffix],'status':state,'observation':note,'matched_config_lines':len(evidence[suffix])})
    return {'tool':'NetScaler Defensive Checker','generated_utc':datetime.now(timezone.utc).isoformat(),'advisory':ADVISORY,'build':build or None,'edition':edition,'build_status':bs,'build_reason':detail,'configuration_provided':bool(config.strip()),'tcp_parameters_provided':bool(tcpparam.strip()),'limitations':['Offline configuration and build assessment, not exploitation confirmation','Absence of matched lines does not prove absence of a prerequisite; export may be incomplete','CVE-2026-88774 and CVE-2026-88777 require manual review of policies, bindings and settings','No indicators-of-compromise assessment is performed'], 'results':results}

def main():
    p=argparse.ArgumentParser(description='Read-only offline assessment of Citrix CTX697096')
    p.add_argument('--config',type=Path,required=True,help='Authorized, locally exported ns.conf')
    p.add_argument('--build',help='Build, e.g. 14.1-73.20 (optional; unknown if missing)')
    p.add_argument('--edition',choices=('standard','fips','ndcpp'),default='standard')
    p.add_argument('--tcp-params',type=Path,help='Text output of show ns tcpparam (optional)')
    p.add_argument('--output',type=Path,help='Write JSON report to local path')
    args=p.parse_args()
    try:
        conf=args.config.read_text(encoding='utf-8-sig')
        tcp=args.tcp_params.read_text(encoding='utf-8-sig') if args.tcp_params else ''
    except (OSError,UnicodeError) as ex:
        p.error(f'Cannot read input: {ex}')
    if not conf.strip(): p.error('Configuration file is empty; cannot assess preconditions')
    result=evaluate(conf,args.build or '',args.edition,tcp)
    result_text=json.dumps(result,indent=2,ensure_ascii=False)
    if args.output:
        try: args.output.write_text(result_text+'\n',encoding='utf-8')
        except OSError as ex: p.error(f'Cannot write output: {ex}')
    else: print(result_text)
    return 0
if __name__=='__main__':sys.exit(main())
