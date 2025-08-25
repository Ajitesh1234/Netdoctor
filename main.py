
import argparse, urllib.parse
from . import diagnostics, report

def run_site(site):
    host = urllib.parse.urlparse(site).netloc or site
    results = {}
    results["dns"] = diagnostics.resolve_dns(host)
    if results["dns"]["ok"]:
        ip = results["dns"]["ip"]
        results["tcp80"] = diagnostics.tcp_connect(ip, 80)
        results["tcp443"] = diagnostics.tcp_connect(ip, 443)
        results["tls"] = diagnostics.tls_handshake(host)
        results["http"] = diagnostics.http_get(host)
        results["ping"] = diagnostics.ping(host)
        results["traceroute"] = diagnostics.traceroute(host)
    return results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sites", nargs="+", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    allres = {}
    for site in args.sites:
        allres[site] = run_site(site)

    outstr = report.make_report(allres, json_out=args.json)
    if args.out:
        with open(args.out,"w") as f: f.write(outstr)
    else:
        print(outstr)

if __name__=="__main__":
    main()
