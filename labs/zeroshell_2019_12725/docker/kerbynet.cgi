#!/bin/bash
# =============================================================================
#  kerbynet.cgi — Minimal reproduction of the CVE-2019-12725 sink
# =============================================================================
#  This Bash CGI reproduces ONLY the shape of the original vulnerable code:
#  the Section=NoAuthREQ / Action=x509view handler concatenates the
#  attacker-controlled `x509type` query parameter into a sudo command line
#  passed to `sh -c`, which is exactly how ZeroShell ≤ 3.9.0 behaved.
#
#  Vulnerable primitive (do NOT use in production — this is the bug):
#     sh -c "/etc/sudo openssl verify -CApath /etc/ssl/certs/trusted_CAs/ '${x509type}'"
#  Because the inner single-quote wrap can be escaped via %0A%27, a payload
#  like  x509type='\nid\n'  splits the shell line into multiple commands.
# =============================================================================

# --- Parse the query string into bash variables --------------------------------
QS="${QUERY_STRING}"
declare -A PARAMS
IFS='&' read -ra PAIRS <<< "${QS}"
for kv in "${PAIRS[@]}"; do
    k="${kv%%=*}"
    v="${kv#*=}"
    # URL-decode (RFC 3986)
    v_decoded="$(printf '%b' "${v//%/\\x}")"
    PARAMS[$k]="$v_decoded"
done

ACTION="${PARAMS[Action]}"
SECTION="${PARAMS[Section]}"
X509TYPE="${PARAMS[x509type]}"

# --- HTTP headers (always send) -----------------------------------------------
printf 'Content-Type: text/html; charset=ISO-8859-1\r\n'
printf 'Cache-Control: no-cache, must-revalidate\r\n'
printf 'Pragma: no-cache\r\n'
printf '\r\n'

cat <<'HEADER'
<html><head><link rel='stylesheet' type='text/css' href='/default.css'>
<title>X509 View</title></head><body>
HEADER

# --- Dispatch ------------------------------------------------------------------
if [[ "${ACTION}" == "x509view" && "${SECTION}" == "NoAuthREQ" ]]; then
    echo "<font color=#000090><b>X.509 Certificate View</b></font><br>"
    echo "<font color=#0000b0>'${X509TYPE}': <i></i></font><br>"
    echo "<font color=#303030>Status: command output below</font><br>"
    echo "<pre>"

    # ===== THE VULNERABLE SINK ================================================
    # NOTE: this is intentionally unsafe — it is the exact pattern that CVE-2019-12725 exploits.
    # apache (www-data) runs as UID 1000-ish; the sudoers entry lets it call openssl/tar NOPASSWD.
    sh -c "/etc/sudo openssl verify -CApath /etc/ssl/certs/ '${X509TYPE}'" 2>&1
    # ===========================================================================

    echo "</pre>"

elif [[ "${ACTION}" == "Render" && "${PARAMS[Object]}" == "sysinfo" ]]; then
    echo "<h2>ZeroShell Simulation — sysinfo</h2>"
    echo "<pre>"
    uname -a
    uptime
    echo "</pre>"

else
    echo "<h2>kerbynet</h2><p>Unknown action: ${ACTION}</p>"
fi

cat <<'FOOTER'
</body></html>
FOOTER
