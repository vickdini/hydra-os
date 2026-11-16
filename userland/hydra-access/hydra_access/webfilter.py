"""Family web filter (Home): per-child website blocking in Firefox.

Firefox reads its AutoConfig file (hydra.cfg in its install folder) at every start; for a
child with filtering on, it locks Firefox's proxy setting to a proxy auto-config script
(/etc/hydra/access/web/<child>.pac) that sends blocked sites to an address that refuses
connections. Locked settings cannot be changed in Firefox's own settings, and the files
are root's. Other users are not affected.

Limits (said in the app): other browsers are not filtered (block them with "Apps"), and
DNS over HTTPS is turned off for filtered children so the filter cannot be bypassed.
"""
import json
import os

FIREFOX_DIRS = ["/usr/lib/firefox", "/usr/lib/firefox-esr", "/opt/firefox"]
WEB = "/etc/hydra/access/web"
PREF_NAME = "hydra-autoconfig.js"
CFG_NAME = "hydra.cfg"


def pac_text(mode, sites):
    sites = sorted({s.strip().lower().lstrip("*.").split("/")[0] for s in sites if s.strip()})
    return """// Hydra Family web filter (generated; changes are overwritten)
var SITES = %s;
function listed(host) {
  host = host.toLowerCase();
  for (var i = 0; i < SITES.length; i++)
    if (host == SITES[i] || dnsDomainIs(host, "." + SITES[i])) return true;
  return false;
}
function FindProxyForURL(url, host) {
  var blocked = %s;
  return blocked ? "PROXY 127.0.0.1:9" : "DIRECT";
}
""" % (json.dumps(sites), "listed(host)" if mode == "block" else "!listed(host) && !isPlainHostName(host)")


def apply(cfg):
    children = cfg.get("family", {}).get("children", {})
    filtered = {n: c["web"] for n, c in children.items() if c.get("web", {}).get("mode") in ("block", "allow")}
    os.makedirs(WEB, exist_ok=True)
    os.chmod(WEB, 0o755)
    for f in os.listdir(WEB):
        if f.endswith(".pac") and f[:-4] not in filtered:
            os.unlink(os.path.join(WEB, f))
    for name, w in filtered.items():
        p = os.path.join(WEB, name + ".pac")
        with open(p, "w", encoding="utf-8") as f:
            f.write(pac_text(w["mode"], w.get("sites", [])))
        os.chmod(p, 0o644)
    for d in FIREFOX_DIRS:
        if not os.path.isdir(d):
            continue
        pref = os.path.join(d, "defaults", "pref", PREF_NAME)
        cfgf = os.path.join(d, CFG_NAME)
        if not filtered:
            for f in (pref, cfgf):
                if os.path.exists(f):
                    os.unlink(f)
            continue
        os.makedirs(os.path.dirname(pref), exist_ok=True)
        with open(pref, "w", encoding="utf-8") as f:
            f.write('// Hydra Family web filter\npref("general.config.filename", "%s");\npref("general.config.obscure_value", 0);\n' % CFG_NAME)
        users = {n: "file://%s/%s.pac" % (WEB, n) for n in filtered}
        with open(cfgf, "w", encoding="utf-8") as f:
            f.write("// Hydra Family web filter (generated)\n"
                    "var hydraPac = %s;\n"
                    "var hydraUser = getenv(\"USER\") || getenv(\"LOGNAME\");\n"
                    "if (hydraPac[hydraUser]) {\n"
                    "  lockPref(\"network.proxy.type\", 2);\n"
                    "  lockPref(\"network.proxy.autoconfig_url\", hydraPac[hydraUser]);\n"
                    "  lockPref(\"network.trr.mode\", 5);\n"
                    "  lockPref(\"browser.privatebrowsing.autostart\", false);\n"
                    "}\n" % json.dumps(users))
        os.chmod(pref, 0o644)
        os.chmod(cfgf, 0o644)
