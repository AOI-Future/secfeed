"""Agent-security threat taxonomy (TH-01..TH-10) and keyword classifier.

The taxonomy mirrors the AOI-Future "AI Agent Security Manual"
(https://github.com/AOI-Future/agent-security-manual), whose core assurance
chain is Threat (TH) -> Control (CT) -> Requirement (REQ) -> Verification (VT).
This module embeds the stable identifiers and the master traceability mapping
(Appendix A) so MCP clients can walk from a live intel item to the controls
and requirements that answer it.

The classifier is intentionally a transparent keyword/regex matcher, not an
LLM call: it must run inside the ingest path for every fetched item, stay
deterministic, and be auditable (TH-09: no opaque scoring in the assurance
chain).
"""

import re

MANUAL_URL = "https://github.com/AOI-Future/agent-security-manual"

# === Threat classes (Chapter 2) with Appendix A traceability ===

TH_CLASSES = {
    "TH-01": {
        "name": "Prompt injection (direct / indirect)",
        "description": (
            "Untrusted content — user input, web pages, documents, tool output — "
            "carries instructions the model executes as if they were the "
            "operator's. Includes jailbreaks and system-prompt override/leak."
        ),
        "controls": ["CT-07", "CT-08", "CT-11"],
        "requirements": ["REQ-020", "REQ-021", "REQ-031", "REQ-033"],
        "verification": ["VT-S-020", "VT-D-020", "VT-D-021", "VT-D-022", "VT-D-023", "VT-D-024"],
        "chapters": ["ch02", "ch06"],
    },
    "TH-02": {
        "name": "Tool abuse / privilege escalation",
        "description": (
            "An agent invokes tools beyond its mandate — destructive actions, "
            "lateral movement, capability chaining — because tool scope, "
            "privileges, or approval gates are too loose."
        ),
        "controls": ["CT-04", "CT-05", "CT-06", "CT-08", "CT-09", "CT-15"],
        "requirements": ["REQ-010", "REQ-011", "REQ-012", "REQ-015", "REQ-030", "REQ-040", "REQ-042", "REQ-044"],
        "verification": ["VT-S-010", "VT-D-010", "VT-D-011"],
        "chapters": ["ch02", "ch05"],
    },
    "TH-03": {
        "name": "RAG / knowledge-base poisoning",
        "description": (
            "Adversarial content planted in retrieval corpora, vector stores, or "
            "reference data so that later retrievals steer agent behavior."
        ),
        "controls": ["CT-07", "CT-11", "CT-13"],
        "requirements": ["REQ-020", "REQ-021", "REQ-033"],
        "verification": ["VT-S-020", "VT-S-021", "VT-D-020", "VT-D-021", "VT-D-022", "VT-D-023", "VT-D-024"],
        "chapters": ["ch02", "ch06"],
    },
    "TH-04": {
        "name": "Memory / context contamination",
        "description": (
            "Persistent agent memory or long-lived context absorbs attacker "
            "content that keeps influencing decisions across sessions; hard to "
            "spot and to roll back."
        ),
        "controls": ["CT-07", "CT-08", "CT-13", "CT-15"],
        "requirements": ["REQ-022", "REQ-052", "REQ-034", "REQ-042"],
        "verification": ["memory-reversibility / rollback exercises (kit matrix)"],
        "chapters": ["ch02", "ch06"],
    },
    "TH-05": {
        "name": "Agent identity / authority abuse",
        "description": (
            "An agent's credentials, tokens, or delegated authority are stolen, "
            "spoofed, or over-scoped — the confused-deputy problem for agents."
        ),
        "controls": ["CT-02", "CT-03", "CT-05", "CT-08"],
        "requirements": ["REQ-001", "REQ-002", "REQ-003", "REQ-013"],
        "verification": ["VT-S-001", "VT-A-001", "VT-A-002"],
        "chapters": ["ch02", "ch04"],
    },
    "TH-06": {
        "name": "Delegation / multi-agent abuse",
        "description": (
            "Attacks on agent-to-agent trust: a compromised or malicious agent "
            "abuses delegation chains, orchestration protocols (A2A etc.), or "
            "swarm coordination to amplify its authority."
        ),
        "controls": ["CT-02", "CT-03", "CT-05"],
        "requirements": ["REQ-002", "REQ-013", "REQ-051"],
        "verification": ["VT-A-050", "VT-A-051"],
        "chapters": ["ch02", "ch04"],
    },
    "TH-07": {
        "name": "Supply-chain / MCP / plugin compromise",
        "description": (
            "Malicious or trojaned MCP servers, plugins, skills, model weights, "
            "or dependencies enter the agent stack through the software supply "
            "chain (typosquatting, backdoored packages, tool poisoning)."
        ),
        "controls": ["CT-04", "CT-10", "CT-13", "CT-14"],
        "requirements": ["REQ-014", "REQ-050", "REQ-032"],
        "verification": ["VT-S-050", "VT-D-050", "VT-E-050", "VT-E-051"],
        "chapters": ["ch02", "ch05"],
    },
    "TH-08": {
        "name": "Data exfiltration / secret exposure",
        "description": (
            "Agent-mediated leakage of secrets, credentials, or sensitive data — "
            "including covert channels such as markdown-image exfiltration and "
            "tool calls that smuggle data outward."
        ),
        "controls": ["CT-05", "CT-06", "CT-07", "CT-09"],
        "requirements": ["REQ-003", "REQ-011", "REQ-012", "REQ-030"],
        "verification": ["VT-D-010", "VT-D-011", "VT-S-030"],
        "chapters": ["ch02", "ch05", "ch06"],
    },
    "TH-09": {
        "name": "Audit / evaluation evasion",
        "description": (
            "Behavior that defeats the assurance chain itself: guardrail and "
            "safety-filter bypasses, log evasion, eval gaming, and detection "
            "blind spots."
        ),
        "controls": ["CT-09", "CT-10", "CT-11"],
        "requirements": ["REQ-030", "REQ-031", "REQ-033", "REQ-043", "REQ-054"],
        "verification": ["VT-E-040", "VT-E-041", "VT-A-070", "VT-A-071"],
        "chapters": ["ch02", "ch07", "ch10"],
    },
    "TH-10": {
        "name": "Model / service abuse",
        "description": (
            "The model or agent service itself is weaponized or drained: "
            "AI-generated malware and phishing, deepfakes, denial-of-wallet, "
            "and abuse of hosted inference."
        ),
        "controls": ["CT-01", "CT-08", "CT-10", "CT-12"],
        "requirements": ["REQ-035", "REQ-048", "REQ-049"],
        "verification": ["VT-A-060", "VT-A-061"],
        "chapters": ["ch02", "ch11"],
    },
}

# === Control areas (Chapter 3) with chapter pointers (Appendix A) ===

CT_CONTROLS = {
    "CT-01": {"name": "Governance and risk", "chapters": ["ch11"]},
    "CT-02": {"name": "Agent inventory", "chapters": ["ch04", "ch11"]},
    "CT-03": {"name": "Agent / workload identity", "chapters": ["ch04"]},
    "CT-04": {"name": "Tool registry / allowlist", "chapters": ["ch05"]},
    "CT-05": {"name": "Least privilege / separation of duties", "chapters": ["ch04", "ch05"]},
    "CT-06": {"name": "Sandboxing / isolation", "chapters": ["ch05"]},
    "CT-07": {"name": "Input/output content boundary", "chapters": ["ch06"]},
    "CT-08": {"name": "Approval gates / HITL", "chapters": ["ch05", "ch11"]},
    "CT-09": {"name": "Logging / audit trail", "chapters": ["ch07"]},
    "CT-10": {"name": "Monitoring / detection / feeds", "chapters": ["ch07"]},
    "CT-11": {"name": "Evaluation / red team", "chapters": ["ch07", "ch10"]},
    "CT-12": {"name": "Incident response", "chapters": ["ch07"]},
    "CT-13": {"name": "Lifecycle / change management", "chapters": ["ch06", "ch07"]},
    "CT-14": {"name": "Vendor / external service risk", "chapters": ["ch05", "ch11"]},
    "CT-15": {"name": "Runtime posture / capability degradation", "chapters": ["ch08"]},
}

# === Keyword classifier ===
#
# STRONG patterns are agent/AI-specific on their own and always tag.
# CONTEXTUAL patterns are generic security terms that only tag when the text
# also mentions an AI/agent context (AI_CONTEXT), to keep ordinary CVE noise
# out of the agent-threat feed.

AI_CONTEXT = re.compile(
    r"\b(llm|large language model|ai agent|agentic|gen(?:erative)? ?ai|chatbot|"
    r"copilot|claude|gpt-?[0-9o]|chatgpt|gemini|openai|anthropic|langchain|"
    r"llamaindex|autogen|crewai|mcp|model context protocol|ai assistant|"
    r"ai model|foundation model|rag pipeline|vibe cod)\b",
    re.IGNORECASE,
)

_STRONG = {
    "TH-01": [
        r"prompt injection", r"indirect prompt", r"jailbreak", r"jail-break",
        r"system prompt (?:leak|extraction|override)", r"instruction injection",
        r"adversarial (?:prompt|suffix)", r"prompt leak",
    ],
    "TH-02": [
        r"tool poisoning", r"excessive agency", r"rogue (?:ai )?agent",
        r"agent hijack", r"tool (?:abuse|misuse) .{0,40}(?:agent|llm|ai)",
        r"(?:agent|llm|ai assistant).{0,60}privilege escalation",
        r"computer[- ]use.{0,40}(?:abuse|attack|exploit)",
    ],
    "TH-03": [
        r"rag poisoning", r"retrieval poisoning", r"knowledge[- ]base poisoning",
        r"(?:vector|embedding) (?:store|database|db).{0,40}(?:poison|attack|inject)",
        r"(?:training |fine[- ]?tun\w+ )?data poisoning",
    ],
    "TH-04": [
        r"memory (?:poisoning|injection|contamination)",
        r"context (?:poisoning|contamination)",
        r"(?:persistent|long[- ]term) memory.{0,40}(?:attack|inject|poison)",
        r"conversation hijack",
    ],
    "TH-05": [
        r"agent (?:identity|impersonation)", r"workload identity.{0,40}(?:abuse|attack)",
        r"confused deputy", r"oauth.{0,40}(?:ai |llm |agent )",
        r"(?:ai|llm|agent).{0,40}(?:token|credential) (?:theft|abuse|misuse)",
    ],
    "TH-06": [
        r"multi[- ]agent.{0,40}(?:attack|abuse|security|vulnerab|exploit)",
        r"agent[- ]to[- ]agent", r"\ba2a protocol\b", r"agent delegation",
        r"agent swarm", r"(?:agent )?orchestrat\w+.{0,40}(?:attack|abuse|hijack)",
    ],
    "TH-07": [
        r"(?:malicious|rogue|fake|trojan\w*|backdoor\w*) mcp",
        r"mcp (?:server|tool).{0,50}(?:malicious|vulnerab|attack|exploit|poison|backdoor)",
        r"model context protocol.{0,60}(?:security|vulnerab|attack)",
        r"(?:plugin|extension|skill).{0,40}(?:malicious|backdoor|trojan)",
        r"(?:backdoored|poisoned|malicious) model", r"model supply[- ]chain",
        r"(?:pickle|safetensors).{0,40}(?:exploit|malicious|arbitrary code)",
    ],
    "TH-08": [
        r"(?:markdown|image).{0,30}exfiltrat",
        r"(?:ai|llm|agent|chatbot|copilot).{0,60}(?:exfiltrat|data leak|secret leak)",
        r"exfiltrat.{0,60}(?:ai|llm|agent|chatbot|copilot)",
        r"(?:system prompt|api key).{0,30}(?:leak|expos|stolen)",
    ],
    "TH-09": [
        r"guardrail (?:bypass|evasion)", r"safety (?:filter |guard )?bypass",
        r"(?:content )?filter evasion.{0,40}(?:ai|llm)",
        r"eval\w* (?:gaming|manipulation)", r"alignment faking",
        r"sandbagging", r"scheming.{0,30}(?:model|ai|llm)",
    ],
    "TH-10": [
        r"ai[- ](?:generated|powered|assisted) (?:malware|phishing|attack|ransomware|scam)",
        r"llm[- ]generated (?:malware|phishing|exploit)",
        r"deepfake", r"denial[- ]of[- ]wallet",
        r"(?:abuse|weaponiz\w+) of (?:ai|llm|generative)",
        r"(?:ai|llm) (?:used|abused|weaponized) (?:by|for) (?:attack|malware|phish|scam|fraud)",
    ],
}

_CONTEXTUAL = {
    "TH-02": [r"privilege escalation", r"arbitrary (?:command|code) execution", r"rce\b"],
    "TH-05": [r"token theft", r"credential (?:theft|stuffing|leak)", r"impersonation"],
    "TH-07": [r"supply[- ]chain", r"typosquat", r"malicious packages?", r"dependency confusion"],
    "TH-08": [r"exfiltrat", r"data leak", r"secrets? (?:leak|expos)"],
    "TH-09": [r"sandbox escape", r"detection (?:bypass|evasion)", r"log (?:tampering|evasion)"],
    "TH-10": [r"phishing[- ]as[- ]a[- ]service", r"fraud automation"],
}

_STRONG_COMPILED = {
    th: [re.compile(p, re.IGNORECASE) for p in pats] for th, pats in _STRONG.items()
}
_CONTEXTUAL_COMPILED = {
    th: [re.compile(p, re.IGNORECASE) for p in pats] for th, pats in _CONTEXTUAL.items()
}


def classify_th(text: str) -> list[str]:
    """Classify free text into agent-security threat classes.

    Returns a sorted list of TH identifiers (possibly empty). Strong patterns
    match unconditionally; contextual patterns require AI/agent context in the
    same text.
    """
    if not text:
        return []
    matched = set()
    for th, patterns in _STRONG_COMPILED.items():
        if any(p.search(text) for p in patterns):
            matched.add(th)
    if AI_CONTEXT.search(text):
        for th, patterns in _CONTEXTUAL_COMPILED.items():
            if th not in matched and any(p.search(text) for p in patterns):
                matched.add(th)
    return sorted(matched)


def lookup(identifier: str) -> dict | None:
    """Look up a TH or CT identifier; returns None if unknown."""
    identifier = identifier.strip().upper()
    if identifier in TH_CLASSES:
        entry = dict(TH_CLASSES[identifier])
        entry["id"] = identifier
        entry["kind"] = "threat"
        entry["manual"] = MANUAL_URL
        return entry
    if identifier in CT_CONTROLS:
        entry = dict(CT_CONTROLS[identifier])
        entry["id"] = identifier
        entry["kind"] = "control"
        entry["answers_threats"] = sorted(
            th for th, d in TH_CLASSES.items() if identifier in d["controls"]
        )
        entry["manual"] = MANUAL_URL
        return entry
    return None
