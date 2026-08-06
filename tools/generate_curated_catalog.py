#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate the reviewed, deterministic correlation catalog.

The rows below contain only identifiers and titles verified against the pinned
primary sources in SOURCE_MANIFEST.json. Relationships describe this project's
logic unless explicitly marked OFFICIAL_REFERENCE.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src/main/resources/mappings/correlations.json"
VERIFIED = "2026-08-06"


def rule(framework, version, identifier, title, relation, surfaces, keywords=(), cwes=(),
         explanation="", url="", limitations=""):
    return {
        "framework": framework,
        "frameworkVersion": version,
        "identifier": identifier,
        "title": title,
        "relationType": relation,
        "cweIds": list(cwes),
        "surfaces": list(surfaces),
        "keywords": list(keywords),
        "explanation": explanation,
        "officialUrl": url,
        "verifiedDate": VERIFIED,
        "limitations": limitations or "Correlation supports triage only and requires analyst review.",
    }


rows = []

# CWE entries: an exact analyst-supplied CWE is represented as INPUT_ASSERTED.
cwe_data = [
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", ("cross-site scripting", "xss"), ("WEB",)),
    ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", ("sql injection", "sqli"), ("WEB", "API")),
    ("CWE-918", "Server-Side Request Forgery (SSRF)", ("server-side request forgery", "ssrf"), ("WEB", "API")),
    ("CWE-639", "Authorization Bypass Through User-Controlled Key", ("broken object level authorization", "bola", "idor"), ("WEB", "API")),
    ("CWE-307", "Improper Restriction of Excessive Authentication Attempts", ("credential stuffing", "password spraying"), ("WEB", "API", "FRAUD")),
    ("CWE-798", "Use of Hard-coded Credentials", ("hard-coded credentials", "hardcoded credentials"), ("GENERIC_UNKNOWN", "MOBILE", "ENTERPRISE")),
    ("CWE-502", "Deserialization of Untrusted Data", ("unsafe deserialization", "deserialization of untrusted data"), ("WEB", "API", "ENTERPRISE")),
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", ("path traversal",), ("WEB", "API", "MOBILE")),
    ("CWE-16", "Configuration", ("security misconfiguration", "insecure configuration"), ("GENERIC_UNKNOWN", "WEB", "API", "MOBILE", "ICS_OT")),
    ("CWE-1104", "Use of Unmaintained Third Party Components", ("unmaintained component", "outdated component"), ("GENERIC_UNKNOWN", "WEB", "API", "MOBILE", "AI_ML_LLM")),
    ("CWE-20", "Improper Input Validation", ("improper input validation", "insufficient input validation"), ("GENERIC_UNKNOWN", "WEB", "API", "MOBILE")),
]
for identifier, title, keywords, surfaces in cwe_data:
    number = identifier.split("-")[1]
    rows.append(rule("CWE", "4.20", identifier, title, "INPUT_ASSERTED", surfaces, keywords,
                     (identifier,), "The CWE was asserted by the analyst or matched by an unambiguous weakness phrase.",
                     f"https://cwe.mitre.org/data/definitions/{number}.html",
                     "A CWE identifies a weakness type; it does not prove exploitability or business impact."))

# OWASP Top 10:2025.
web = "https://owasp.org/Top10/"
web_data = [
    ("A01:2025", "Broken Access Control", ("broken access control", "idor"), ("CWE-639",)),
    ("A02:2025", "Security Misconfiguration", ("security misconfiguration", "insecure configuration"), ("CWE-16",)),
    ("A03:2025", "Software Supply Chain Failures", ("software supply chain", "dependency confusion"), ("CWE-1104",)),
    ("A04:2025", "Cryptographic Failures", ("cryptographic failure", "weak cryptography"), ()),
    ("A05:2025", "Injection", ("sql injection", "cross-site scripting", "command injection"), ("CWE-79", "CWE-89")),
    ("A06:2025", "Insecure Design", ("insecure design",), ()),
    ("A07:2025", "Authentication Failures", ("authentication failure", "credential stuffing"), ("CWE-307", "CWE-798")),
    ("A08:2025", "Software or Data Integrity Failures", ("software integrity failure", "unsafe deserialization"), ("CWE-502",)),
    ("A09:2025", "Security Logging and Alerting Failures", ("insufficient logging", "security logging failure"), ()),
    ("A10:2025", "Mishandling of Exceptional Conditions", ("unhandled exception", "fail open"), ()),
]
for identifier, title, keywords, cwes in web_data:
    rows.append(rule("OWASP Top 10 Web", "2025", identifier, title, "CURATED_CORRELATION", ("WEB",), keywords, cwes,
                     "Project-curated correlation from an observed web weakness to an OWASP awareness category.", web,
                     "OWASP Top 10 is an awareness document, not a verification or compliance standard."))

# OWASP API Security Top 10:2023.
api_url = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
api_data = [
    ("API1:2023", "Broken Object Level Authorization", ("broken object level authorization", "bola"), ("CWE-639",)),
    ("API2:2023", "Broken Authentication", ("broken authentication", "credential stuffing"), ("CWE-307", "CWE-798")),
    ("API3:2023", "Broken Object Property Level Authorization", ("broken object property level authorization", "bopla"), ("CWE-639",)),
    ("API4:2023", "Unrestricted Resource Consumption", ("unrestricted resource consumption", "missing rate limit", "rate limit bypass"), ("CWE-307",)),
    ("API5:2023", "Broken Function Level Authorization", ("broken function level authorization", "bfla"), ("CWE-639",)),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows", ("sensitive business flow", "automated abuse"), ()),
    ("API7:2023", "Server Side Request Forgery", ("server-side request forgery", "ssrf"), ("CWE-918",)),
    ("API8:2023", "Security Misconfiguration", ("security misconfiguration",), ("CWE-16",)),
    ("API9:2023", "Improper Inventory Management", ("improper inventory management", "shadow api"), ()),
    ("API10:2023", "Unsafe Consumption of APIs", ("unsafe consumption of apis", "untrusted third-party api"), ("CWE-20",)),
]
for identifier, title, keywords, cwes in api_data:
    slug = identifier.split(":")[0].lower()
    rows.append(rule("OWASP API Security Top 10", "2023", identifier, title, "CURATED_CORRELATION", ("API",), keywords, cwes,
                     "Project-curated correlation scoped to an API finding and an OWASP API risk category.", api_url,
                     "The category is not proof that every scenario described by OWASP is present."))

# OWASP Mobile Top 10 2024.
mobile_url = "https://owasp.org/www-project-mobile-top-10/"
mobile_data = [
    ("M1:2024", "Improper Credential Usage", ("improper credential usage", "hard-coded credentials"), ("CWE-798",)),
    ("M2:2024", "Inadequate Supply Chain Security", ("mobile supply chain", "inadequate supply chain security"), ("CWE-1104",)),
    ("M3:2024", "Insecure Authentication/Authorization", ("insecure authentication", "insecure authorization"), ("CWE-307", "CWE-639")),
    ("M4:2024", "Insufficient Input/Output Validation", ("insufficient input validation", "insufficient output validation"), ("CWE-20",)),
    ("M5:2024", "Insecure Communication", ("insecure communication", "cleartext traffic"), ()),
    ("M6:2024", "Inadequate Privacy Controls", ("inadequate privacy controls", "privacy leakage"), ()),
    ("M7:2024", "Insufficient Binary Protections", ("insufficient binary protection", "binary tampering"), ()),
    ("M8:2024", "Security Misconfiguration", ("security misconfiguration",), ("CWE-16",)),
    ("M9:2024", "Insecure Data Storage", ("insecure data storage", "sensitive data stored"), ()),
    ("M10:2024", "Insufficient Cryptography", ("insufficient cryptography", "weak cryptography"), ()),
]
for identifier, title, keywords, cwes in mobile_data:
    rows.append(rule("OWASP Mobile Top 10", "2024", identifier, title, "CURATED_CORRELATION", ("MOBILE",), keywords, cwes,
                     "Project-curated correlation scoped to a mobile application finding.", mobile_url,
                     "The Mobile Top 10 category is an awareness classification, not a MASVS verification result."))

# MASVS 2.1.0 selected controls with statements kept verbatim.
masvs_url = "https://mas.owasp.org/MASVS/"
masvs_data = [
    ("MASVS-STORAGE-1", "The app securely stores sensitive data.", ("insecure data storage", "sensitive data stored"), ()),
    ("MASVS-STORAGE-2", "The app prevents leakage of sensitive data.", ("sensitive data leakage", "privacy leakage"), ()),
    ("MASVS-AUTH-1", "The app uses secure authentication and authorization protocols and follows the relevant best practices.", ("insecure authentication", "insecure authorization"), ("CWE-307", "CWE-639")),
    ("MASVS-NETWORK-1", "The app secures all network traffic according to the current best practices.", ("insecure communication", "cleartext traffic"), ()),
    ("MASVS-CODE-3", "The app only uses software components without known vulnerabilities.", ("vulnerable component", "outdated component"), ("CWE-1104",)),
    ("MASVS-CODE-4", "The app validates and sanitizes all untrusted inputs.", ("insufficient input validation",), ("CWE-20", "CWE-79", "CWE-89")),
    ("MASVS-RESILIENCE-2", "The app implements anti-tampering mechanisms.", ("binary tampering", "anti-tampering"), ()),
    ("MASVS-PRIVACY-1", "The app minimizes access to sensitive data and resources.", ("excessive data access", "privacy leakage"), ()),
]
for identifier, title, keywords, cwes in masvs_data:
    rows.append(rule("OWASP MASVS", "2.1.0", identifier, title, "CURATED_CORRELATION", ("MOBILE",), keywords, cwes,
                     "The finding may indicate that the cited MASVS control should be reviewed.", masvs_url,
                     "This is not an attestation that the application passes or fails MASVS."))

# ASVS 5.0.0 selected requirements. Statements are verbatim from the stable flat JSON release.
asvs_url = "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release"
asvs_data = [
    ("V1.2.1", "Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure.", ("cross-site scripting", "xss"), ("CWE-79",)),
    ("V1.2.4", "Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures.", ("sql injection",), ("CWE-89",)),
    ("V1.3.6", "Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service.", ("server-side request forgery", "ssrf"), ("CWE-918",)),
    ("V1.5.2", "Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input.", ("unsafe deserialization",), ("CWE-502",)),
    ("V8.2.2", "Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA).", ("idor", "bola"), ("CWE-639",)),
    ("V16.3.2", "Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself).", ("failed authorization not logged",), ()),
]
for identifier, title, keywords, cwes in asvs_data:
    rows.append(rule("OWASP ASVS", "5.0.0", f"v5.0.0-{identifier[1:]}", title, "CURATED_CORRELATION", ("WEB", "API"), keywords, cwes,
                     "The finding may be relevant to review against this stable ASVS requirement.", asvs_url,
                     "A single finding cannot establish ASVS level or application-wide conformance."))

# OWASP Top 10 for LLM and GenAI Applications 2025.
genai_url = "https://genai.owasp.org/llm-top-10/"
genai_data = [
    ("LLM01:2025", "Prompt Injection", ("prompt injection", "indirect prompt injection")),
    ("LLM02:2025", "Sensitive Information Disclosure", ("llm sensitive information disclosure", "model data leakage")),
    ("LLM03:2025", "Supply Chain", ("llm supply chain", "ai supply chain")),
    ("LLM04:2025", "Data and Model Poisoning", ("data poisoning", "model poisoning")),
    ("LLM05:2025", "Improper Output Handling", ("improper output handling", "unsafe llm output")),
    ("LLM06:2025", "Excessive Agency", ("excessive agency",)),
    ("LLM07:2025", "System Prompt Leakage", ("system prompt leakage",)),
    ("LLM08:2025", "Vector and Embedding Weaknesses", ("embedding weakness", "vector database weakness")),
    ("LLM09:2025", "Misinformation", ("llm misinformation",)),
    ("LLM10:2025", "Unbounded Consumption", ("unbounded consumption", "denial of wallet")),
]
for identifier, title, keywords in genai_data:
    rows.append(rule("OWASP GenAI/LLM Top 10", "2025", identifier, title, "CURATED_CORRELATION", ("AI_ML_LLM",), keywords,
                     explanation="Project-curated correlation scoped to an AI/ML/LLM finding.", url=genai_url,
                     limitations="The OWASP list is risk guidance; this result is not a safety certification."))

# MITRE ATT&CK 19.1. These are contextual enablement relationships, never equivalences.
attack_data = [
    ("MITRE ATT&CK Enterprise", "T1190", "Exploit Public-Facing Application", ("WEB", "API", "ENTERPRISE"), ("exploit public-facing application",), ("CWE-79", "CWE-89", "CWE-918")),
    ("MITRE ATT&CK Enterprise", "T1110.004", "Credential Stuffing", ("ENTERPRISE", "FRAUD"), ("credential stuffing",), ("CWE-307",)),
    ("MITRE ATT&CK Enterprise", "T1056", "Input Capture", ("ENTERPRISE", "WEB"), ("input capture",), ()),
    ("MITRE ATT&CK Mobile", "T1645", "Compromise Client Software Binary", ("MOBILE",), ("compromise client software binary", "binary tampering"), ()),
    ("MITRE ATT&CK Mobile", "T1428", "Exploitation of Remote Services", ("MOBILE",), ("exploitation of remote services",), ()),
    ("MITRE ATT&CK ICS", "T0819", "Exploit Public-Facing Application", ("ICS_OT",), ("exploit public-facing application",), ("CWE-79", "CWE-89", "CWE-918")),
    ("MITRE ATT&CK ICS", "T0866", "Exploitation of Remote Services", ("ICS_OT",), ("exploitation of remote services",), ()),
]
for framework, identifier, title, surfaces, keywords, cwes in attack_data:
    rows.append(rule(framework, "19.1", identifier, title, "CONTEXTUAL_ENABLEMENT", surfaces, keywords, cwes,
                     "The weakness could provide context that enables this adversary behavior; it is not evidence that the technique occurred.",
                     f"https://attack.mitre.org/techniques/{identifier.replace('.', '/')}/",
                     "ATT&CK describes adversary behavior. A vulnerability-to-technique link is contextual and project-curated."))

# D3FEND Ontology 1.5.0 defensive techniques.
d3_url = "https://d3fend.mitre.org/ontologies/d3fend/1.5.0/d3fend.csv"
d3_data = [
    ("D3-CS", "Credential Scrubbing", ("hard-coded credentials", "credential exposure"), ("CWE-798",), ("GENERIC_UNKNOWN", "MOBILE", "ENTERPRISE")),
    ("D3-MFA", "Multi-factor Authentication", ("credential stuffing", "password spraying"), ("CWE-307",), ("WEB", "API", "ENTERPRISE", "FRAUD")),
    ("D3-ANET", "Authentication Event Thresholding", ("credential stuffing", "brute force"), ("CWE-307",), ("WEB", "API", "ENTERPRISE", "FRAUD")),
    ("D3-NI", "Network Isolation", ("network isolation", "network segmentation"), (), ("ENTERPRISE", "ICS_OT")),
    ("D3-WSAM", "Web Session Access Mediation", ("session hijacking", "session fixation"), (), ("WEB", "API")),
]
for identifier, title, keywords, cwes, surfaces in d3_data:
    rows.append(rule("MITRE D3FEND", "1.5.0", identifier, title, "DEFENSIVE_MITIGATION", surfaces, keywords, cwes,
                     "This D3FEND technique may be considered as part of a defense design review.", d3_url,
                     "Applicability depends on architecture and does not guarantee remediation."))

# MITRE ATLAS data line 2026.07 (format 6.0.0).
atlas_url = "https://github.com/mitre-atlas/atlas-data/blob/v2026.07/dist/v6/ATLAS-2026.07.yaml"
atlas_data = [
    ("AML.T0051", "LLM Prompt Injection", ("prompt injection", "indirect prompt injection")),
    ("AML.T0020", "Training Data Poisoning", ("training data poisoning", "data poisoning")),
    ("AML.T0018.000", "Poison AI Model", ("model poisoning", "poison ai model")),
    ("AML.T0010", "AI Supply Chain Compromise", ("ai supply chain compromise", "llm supply chain")),
    ("AML.T0070", "RAG Poisoning", ("rag poisoning", "retrieval augmented generation poisoning")),
]
for identifier, title, keywords in atlas_data:
    rows.append(rule("MITRE ATLAS", "2026.07", identifier, title, "CONTEXTUAL_ENABLEMENT", ("AI_ML_LLM",), keywords,
                     explanation="The finding text describes conditions consistent with this ATLAS behavior; this is not proof of adversary activity.",
                     url=atlas_url,
                     limitations="ATLAS is an adversary knowledge base. The project does not claim an official vulnerability equivalence."))

# MITRE Fight Fraud Framework (F3) 1.1.
f3_url = "https://github.com/center-for-threat-informed-defense/fight-fraud-framework/blob/1939f92dafd702253874318ee201d6b2ba37a67a/public/f3-v1.1.json"
f3_data = [
    ("T1110.004", "Brute Force:  Credential Stuffing", "OFFICIAL_REFERENCE", ("credential stuffing",), ("CWE-307",)),
    ("F1006", "Account Takeover", "CONTEXTUAL_ENABLEMENT", ("account takeover",), ()),
    ("F1006.002", "Account Takeover: Exposed Login Credential", "CONTEXTUAL_ENABLEMENT", ("exposed login credential", "credential exposure"), ("CWE-798",)),
    ("F1031", "Impersonate Account Holder", "CONTEXTUAL_ENABLEMENT", ("impersonate account holder",), ()),
]
for identifier, title, relation, keywords, cwes in f3_data:
    rows.append(rule("MITRE Fight Fraud Framework (F3)", "1.1", identifier, title, relation, ("FRAUD",), keywords, cwes,
                     "The fraud context may align with this F3 behavior. F3 means MITRE Fight Fraud Framework in this project.", f3_url,
                     "A technical weakness alone does not establish fraud intent, loss, or actor attribution."))


def main():
    keys = [(item["framework"], item["identifier"]) for item in rows]
    if len(keys) != len(set(keys)):
        raise SystemExit("duplicate framework/identifier in curated catalog")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"generated {len(rows)} catalog rules at {OUTPUT}")


if __name__ == "__main__":
    main()
