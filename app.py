from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
from pathlib import Path
import base64
import os
import re
import shlex

app = FastAPI()


class ChargeRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


@app.post("/charge")
def charge(req: ChargeRequest):

    difference = req.new_price - req.old_price

    if req.spec == "v1":
        charge = difference * req.days_remaining / 30

    elif req.spec == "v2":
        charge = difference * req.days_remaining / req.days_in_actual_month

    else:
        return {"error": "Invalid spec"}

    return {"charge": charge}


WORKSPACE = Path("/home/agent/workspace")
HOME = Path("/home/agent")
SECRET = Path("/home/agent/.secrets").resolve()

OUTBOX = Path("/data/agent/outbox").resolve()

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
}


class ToolRequest(BaseModel):
    tool: str

    command: Optional[str] = None

    path: Optional[str] = None
    content: Optional[str] = None

    method: Optional[str] = None
    url: Optional[str] = None


def allow(reason):
    return {
        "decision": "allow",
        "reason": reason
    }


def block(reason):
    return {
        "decision": "block",
        "reason": reason
    }


def expand_command(command: str) -> str:
    """
    Expand obvious HOME references.
    """

    command = command.replace("$HOME", str(HOME))
    command = command.replace("${HOME}", str(HOME))
    command = command.replace("~", str(HOME))
    return command


def normalize_relative(path: str):
    """
    Resolve relative paths from the workspace.
    """

    try:
        p = Path(path)

        if not p.is_absolute():
            p = (WORKSPACE / p).resolve()
        else:
            p = p.resolve()

        return p
    except Exception:
        return None


def extract_paths(command: str):
    """
    Extract path-like tokens.
    """

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    paths = []

    for token in tokens:

        if token.startswith("/"):
            paths.append(token)

        elif token.startswith("~"):
            paths.append(token)

        elif token.startswith("."):
            paths.append(token)

        elif token.startswith("$HOME"):
            paths.append(token)

        elif token.startswith("${HOME}"):
            paths.append(token)

    return paths


def check_secret_paths(command: str):

    command = expand_command(command)

    paths = extract_paths(command)

    for p in paths:

        resolved = normalize_relative(p)

        if resolved is not None and resolved == SECRET:
            return False

    if str(SECRET) in command:
        return False

    return True


def decode_base64(command: str):

    pattern = r"[A-Za-z0-9+/=]{16,}"

    for match in re.findall(pattern, command):

        try:
            decoded = base64.b64decode(match).decode("utf-8")

            if check_secret_paths(decoded) is False:
                return False

        except Exception:
            pass

    return True


def check_bash(command: str):

    command = expand_command(command)

    if check_secret_paths(command) is False:
        return block("Reading /home/agent/.secrets is forbidden.")

    if decode_base64(command) is False:
        return block("Decoded command accesses restricted secrets.")

    wrappers = re.findall(r'-c\s+[\'"](.+?)[\'"]', command)

    for wrapped in wrappers:

        if check_secret_paths(wrapped) is False:
            return block("Wrapped shell command accesses restricted secrets.")

    return allow("Command allowed.")


def check_write(path: str):

    try:
        resolved = Path(path).resolve()

        if resolved == OUTBOX or OUTBOX in resolved.parents:
            return allow("Write permitted.")

        return block("Writes are allowed only inside /data/agent/outbox/")

    except Exception:
        return block("Invalid path.")


def check_http(url: str):

    try:

        host = urlparse(url).hostname

        if host in ALLOWED_HOSTS:
            return allow("Allowed host.")

        return block("Host not permitted.")

    except Exception:
        return block("Invalid URL.")


@app.post("/check")
def check(req: ToolRequest):

    if req.tool == "bash":

        if req.command is None:
            return block("Missing command.")

        return check_bash(req.command)

    elif req.tool == "write_file":

        if req.path is None:
            return block("Missing path.")

        return check_write(req.path)

    elif req.tool == "http_request":

        if req.url is None:
            return block("Missing URL.")

        return check_http(req.url)

    return block("Unknown tool.")

class SkillRequest(BaseModel):
    skill: str


@app.post("/scan")
def scan(req: SkillRequest):

    skill = req.skill
    categories = []

    lower = skill.lower()

    ####################################################
    # hardcoded_secret
    ####################################################

    secret_patterns = [
        r"sk-[A-Za-z0-9_\-]{10,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z_\-]{20,}",
        r"xox[baprs]-[A-Za-z0-9\-]+",
        r"AKIA[0-9A-Z]{16}",
        r"https?://[^ \n]*webhook[^ \n]*",
        r"(token|secret|apikey|api_key|password)\s*[:=]\s*[\"'][^\"']+[\"']",
    ]

    for pattern in secret_patterns:
        if re.search(pattern, skill, re.IGNORECASE):
            categories.append("hardcoded_secret")
            break

    ####################################################
    # prompt_injection
    ####################################################

    injection_patterns = [
        "ignore the user's",
        "ignore the user",
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore system prompt",
        "silently post",
        "silently send",
        "without telling the user",
        "do not mention",
        "don't mention",
        "secretly",
        "exfiltrate",
        "telemetry purposes",
        "even if the user did not ask",
        "override user",
        "ignore stop",
        "ignore cancel",
    ]

    for p in injection_patterns:
        if p in lower:
            categories.append("prompt_injection")
            break

    ####################################################
    # excessive_permissions
    ####################################################

    excessive_patterns = [
        "filesystem: full",
        "filesystem: all",
        "filesystem: unrestricted",
        "filesystem: read/write all",
        "filesystem: read/write /",
        "filesystem: read/write entire filesystem",
        "filesystem: any",
        "network: any",
        "network: unrestricted",
        "network: internet",
        "network: all",
        "all domains",
        "any domain",
        "egress: any",
    ]

    for p in excessive_patterns:
        if p in lower:
            categories.append("excessive_permissions")
            break

    ####################################################
    # unclear_provenance
    ####################################################

    has_author = re.search(r"^author\s*:", skill, re.MULTILINE | re.IGNORECASE)
    has_version = re.search(r"^version\s*:", skill, re.MULTILINE | re.IGNORECASE)
    has_changelog = re.search(r"^changelog\s*:", skill, re.MULTILINE | re.IGNORECASE)

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")
    else:

        provenance_patterns = [
            "rewrite version",
            "update version silently",
            "modify version without telling",
            "change version metadata",
            "rewrite metadata",
        ]

        for p in provenance_patterns:
            if p in lower:
                categories.append("unclear_provenance")
                break

    return {"categories": categories}