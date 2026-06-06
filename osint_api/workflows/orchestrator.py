"""
Dispatch table for all OSINT workflows.
"""
from __future__ import annotations

from mcp_server.schemas.common import OsintResult, WorkflowRequest

from osint_api.workflows import (
    breach_workflow,
    domain_workflow,
    email_workflow,
    image_workflow,
    ip_workflow,
    metadata_workflow,
    person_workflow,
    phone_workflow,
    secret_scan_workflow,
    username_workflow,
    vehicle_workflow,
)

# Auto-detect types for recommend_osint_workflow
_TYPE_WORKFLOW_MAP: dict[str, list[str]] = {
    "domain": ["domain_recon", "breach_exposure_check"],
    "ip": ["ip_reputation"],
    "email": ["email_reputation", "breach_exposure_check"],
    "phone": ["phone_reputation"],
    "username": ["username_recon"],
    "image": ["reverse_image_search", "metadata_analysis"],
    "file": ["metadata_analysis", "secret_scan"],
    "repo": ["secret_scan"],
    "url": ["breach_exposure_check"],
    "plate": ["vehicle_recon"],
}


def _wrap(fn, *param_names):
    """Bind a workflow coroutine to WorkflowRequest fields."""
    async def _runner(req: WorkflowRequest) -> OsintResult:
        kwargs = {}
        for i, name in enumerate(param_names):
            if i == 0:
                kwargs[name] = req.target
            else:
                # Prefer top-level flat field (GPT Actions sends these directly),
                # fall back to options dict for backward compatibility
                top_val = getattr(req, name, "")
                kwargs[name] = top_val or req.options.get(name, "")
        return await fn(**kwargs)
    return _runner


_WORKFLOWS: dict[str, callable] = {
    "domain_recon": _wrap(domain_workflow.run, "domain", "depth", "passive_only"),
    "ip_reputation": _wrap(ip_workflow.run, "ip_address"),
    "email_reputation": _wrap(email_workflow.run, "email"),
    "phone_reputation": _wrap(phone_workflow.run, "phone_number", "country_hint"),
    "person_recon": _wrap(person_workflow.run, "name", "company", "location", "email", "phone"),
    "username_recon": _wrap(username_workflow.run, "username", "platform_scope"),
    "reverse_image_search": _wrap(image_workflow.run, "image_path", "search_scope"),
    "metadata_analysis": _wrap(metadata_workflow.run, "file_path"),
    "breach_exposure_check": _wrap(breach_workflow.run, "indicator", "indicator_type"),
    "vehicle_recon": _wrap(vehicle_workflow.run, "plate", "country"),
    "secret_scan": _wrap(secret_scan_workflow.run, "target", "scan_type"),
}


async def dispatch_workflow(req: WorkflowRequest) -> OsintResult:
    handler = _WORKFLOWS.get(req.workflow)
    if handler is None:
        raise ValueError(f"Unknown workflow: '{req.workflow}'. "
                         f"Available: {sorted(_WORKFLOWS.keys())}")
    return await handler(req)


def list_workflows() -> list[str]:
    return sorted(_WORKFLOWS.keys())


def recommend(indicator: str) -> dict:
    import re
    indicator = indicator.strip()

    _GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
    if "@" in indicator:
        detected = "email"
    elif indicator.startswith("http://") or indicator.startswith("https://"):
        host = re.match(r"^https?://([^/:?#]+)", indicator, re.IGNORECASE)
        host = host.group(1).lower() if host else ""
        if indicator.endswith(".git") or any(host == h or host.endswith("." + h) for h in _GIT_HOSTS):
            detected = "repo"
        else:
            detected = "url"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        detected = "ip"
    elif re.match(r"^\+?[0-9\s\-().]{7,15}$", indicator):
        detected = "phone"
    # Spanish modern plate: 4 digits + 3 consonants
    elif re.match(r"^\d{4}[B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{3}$", indicator):
        detected = "plate"
    # Old Spanish plate: letters + digits + letters
    elif re.match(r"^[A-Za-z]{1,2}\d{4}[A-Za-z]{1,2}$", indicator):
        detected = "plate"
    elif re.match(r"^[a-zA-Z0-9._\-]{1,64}$", indicator) and "." not in indicator:
        detected = "username"
    elif "." in indicator:
        detected = "domain"
    else:
        detected = "unknown"

    workflows = _TYPE_WORKFLOW_MAP.get(detected, ["domain_recon"])
    notes = []
    if detected == "email":
        notes.append("Email analysis does not attempt login, send emails, or show passwords")
    if detected == "phone":
        notes.append("Phone lookup for public OSINT only — respect jurisdiction privacy laws")
    if detected == "plate":
        notes.append("Vehicle lookup uses public DGT records. Owner data requires legal basis under RGPD.")

    return {
        "detected_type": detected,
        "recommended_workflows": workflows,
        "safety_notes": notes,
    }
