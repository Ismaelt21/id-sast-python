# VULNERABLE: Command Injection via exec / execv / execve - Training Sample
# CWE-78 / CWE-77: Command Injection
# Severity: CRITICAL
# Description: os.exec* family functions called with user-supplied arguments

import os


def run_program(program_name):
    """VULNERABLE: execvp with user-controlled program name."""
    # VULN: program_name = "/bin/bash" or "/usr/bin/python3 -c 'import os;os.system(\"id\")'"
    os.execvp(program_name, [program_name])


def run_with_args(program, args_string):
    """VULNERABLE: User controls both the program and its arguments."""
    # VULN: args_string split on spaces — trivial to inject flags like --config /etc/shadow
    args = args_string.split()
    os.execvp(program, [program] + args)


def switch_process(binary, env_var_name, env_var_value):
    """VULNERABLE: execve with user-controlled environment variable."""
    # VULN: attacker can set LD_PRELOAD or PATH to hijack execution
    env = os.environ.copy()
    env[env_var_name] = env_var_value          # VULN: arbitrary env manipulation
    os.execve(binary, [binary], env)


def open_editor(filename):
    """VULNERABLE: Launches editor with user-controlled filename via execl."""
    # VULN: filename = "/etc/passwd" leaks sensitive file; shell metachar risk
    os.execl("/usr/bin/vim", "vim", filename)


def run_interpreter(lang, script_path):
    """VULNERABLE: Interpreter selection from user input."""
    interpreters = {
        "python": "/usr/bin/python3",
        "ruby": "/usr/bin/ruby",
        "perl": "/usr/bin/perl",
        "bash": "/bin/bash",       # VULN: attacker picks bash
    }
    interp = interpreters.get(lang, "/usr/bin/python3")
    # VULN: script_path can be /etc/passwd or a malicious uploaded file
    os.execl(interp, interp, script_path)


def apply_patch(patch_file):
    """VULNERABLE: patch utility executed with user path via execlp."""
    # VULN: patch_file = "../../evil.patch" or absolute path to malicious patch
    os.execlp("patch", "patch", "-p1", "-i", patch_file)


def launch_service(service_name, config_path):
    """VULNERABLE: Daemon launch with attacker-controlled config."""
    # VULN: config_path can override service config with malicious settings
    os.execvp(service_name, [service_name, "--config", config_path])


def run_shell_builtin(command):
    """VULNERABLE: Spawns a shell and passes user command to -c flag."""
    # VULN: Equivalent to shell=True — full shell injection possible
    os.execl("/bin/sh", "sh", "-c", command)


def hot_reload(module_path):
    """VULNERABLE: Replaces current process with a new Python interpreter running user module."""
    # VULN: module_path = "/tmp/evil.py" — runs arbitrary uploaded code
    os.execl("/usr/bin/python3", "python3", module_path)