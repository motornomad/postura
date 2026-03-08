"""OWASP Top 10 2021 knowledge loader — P4.1c

Embeds hardcoded OWASP Top 10 2021 entries into ChromaDB collection "owasp".
No download required — this is stable, well-known content.
"""
from __future__ import annotations

import logging

from postura.knowledge.embedder import get_or_create_collection, upsert_documents

logger = logging.getLogger(__name__)

# OWASP Top 10 2021 — complete structured entries
_OWASP_TOP10: list[dict] = [
    {
        "id": "A01:2021",
        "title": "Broken Access Control",
        "cwe_ids": ["CWE-200", "CWE-201", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-732", "CWE-862", "CWE-863"],
        "description": (
            "Access control enforces policy such that users cannot act outside of their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification, or destruction of all data, "
            "or performing a business function outside the user's limits. "
            "Common vulnerabilities include: bypassing access control checks by modifying URLs or HTML pages, "
            "allowing primary key changes to another user's record, elevation of privilege, "
            "metadata manipulation (JWT token replay, cookie tampering), CORS misconfiguration, "
            "force browsing to authenticated or privileged pages, accessing API without POST/PUT/DELETE access controls."
        ),
        "mitigations": (
            "Deny by default, except for public resources. "
            "Implement access control mechanisms once and reuse throughout the application. "
            "Log access control failures, alert admins when appropriate. "
            "Rate limit API and controller access to minimize harm from automated attack tooling. "
            "Invalidate stateful session identifiers on logout. "
            "JWT tokens should be short-lived."
        ),
    },
    {
        "id": "A02:2021",
        "title": "Cryptographic Failures",
        "cwe_ids": ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329"],
        "description": (
            "Formerly known as Sensitive Data Exposure. "
            "Focuses on failures related to cryptography (or lack thereof) which often leads to exposure of sensitive data. "
            "Common issues: data transmitted in clear text (HTTP, SMTP, FTP), use of old or weak cryptographic algorithms, "
            "default or weak or reused crypto keys, improper certificate validation, "
            "passwords stored using unsalted or weak hashes, deprecated hash functions like MD5 or SHA1, "
            "deprecated padding methods like PKCS#1 v1.5, cryptographic errors used as oracle."
        ),
        "mitigations": (
            "Classify data processed, stored, or transmitted and identify which is sensitive. "
            "Do not store sensitive data unnecessarily. "
            "Ensure strong adaptive and salted hashing for passwords (Argon2, scrypt, bcrypt, PBKDF2). "
            "Encrypt all data in transit with secure protocols (TLS 1.2+). "
            "Disable caching for responses that contain sensitive data. "
            "Store passwords using bcrypt, scrypt, Argon2id, or PBKDF2."
        ),
    },
    {
        "id": "A03:2021",
        "title": "Injection",
        "cwe_ids": ["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95"],
        "description": (
            "An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized. "
            "Injection types include: SQL, NoSQL, OS command, LDAP, Expression Language, ORM, XML, and others. "
            "SQL injection occurs when hostile data is sent to an interpreter as part of a command or query. "
            "CWE-89: SQL injection, CWE-79: XSS, CWE-78: OS command injection. "
            "Dynamic queries and non-parameterized calls without context-aware escaping are the root cause. "
            "An attacker can use injection to extract, modify, or delete database data."
        ),
        "mitigations": (
            "Use a safe API that avoids the use of the interpreter entirely or provides a parameterized interface. "
            "Use positive server-side input validation. "
            "For residual dynamic queries, escape special characters using the specific escape syntax for that interpreter. "
            "Use LIMIT and other SQL controls within queries to prevent mass disclosure of records in case of SQL injection."
        ),
    },
    {
        "id": "A04:2021",
        "title": "Insecure Design",
        "cwe_ids": ["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-434", "CWE-444"],
        "description": (
            "A new category for 2021 focusing on risks related to design and architectural flaws. "
            "Insecure design is not the source of all other Top 10 risk categories. "
            "There is a difference between insecure design and insecure implementation. "
            "Insecure design cannot be fixed by a perfect implementation as by definition the controls were never created. "
            "Missing or ineffective control design is the source of this category."
        ),
        "mitigations": (
            "Establish a secure development lifecycle with security professionals for evaluating and designing security controls. "
            "Use threat modeling for critical authentication, access control, business logic, and key flows. "
            "Integrate security language and controls into user stories. "
            "Write unit and integration tests to validate that all critical flows are resistant to the threat model."
        ),
    },
    {
        "id": "A05:2021",
        "title": "Security Misconfiguration",
        "cwe_ids": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-266", "CWE-520", "CWE-526", "CWE-537", "CWE-538", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1021", "CWE-1173"],
        "description": (
            "Security misconfiguration is the most commonly seen issue. "
            "Application might be misconfigured due to: missing security hardening, unnecessary features enabled or installed, "
            "default accounts and passwords, overly informative error messages, outdated or vulnerable components, "
            "missing security headers, server sending detailed version information, "
            "CORS configured as wildcard allowing all origins, DEBUG mode enabled in production, "
            "cloud storage buckets publicly accessible."
        ),
        "mitigations": (
            "Repeatable hardening process, fast and easy to deploy. "
            "Development, QA, and production environments should all be configured identically. "
            "A minimal platform without unnecessary features, components, documentation, and samples. "
            "Review and update configurations appropriate to all security notes, updates, and patches as part of the patch management process. "
            "Segmented application architecture for security separation between components or tenants via segmentation, containerization, or cloud security groups."
        ),
    },
    {
        "id": "A06:2021",
        "title": "Vulnerable and Outdated Components",
        "cwe_ids": ["CWE-1104"],
        "description": (
            "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. "
            "If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. "
            "Vulnerable when you do not know the versions of all components you use. "
            "The software is vulnerable, unsupported, or out of date: OS, web/application server, DBMS, APIs, libraries, runtimes. "
            "You do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion. "
            "Software developers do not test the compatibility of updated, upgraded, or patched libraries."
        ),
        "mitigations": (
            "Remove unused dependencies, unnecessary features, components, files, and documentation. "
            "Continuously inventory the versions of both client-side and server-side components. "
            "Monitor sources like CVE and NVD for vulnerabilities in your components. "
            "Use tools like OWASP Dependency Check, Retire.js, pip-audit. "
            "Only obtain components from official sources over secure links."
        ),
    },
    {
        "id": "A07:2021",
        "title": "Identification and Authentication Failures",
        "cwe_ids": ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"],
        "description": (
            "Formerly Broken Authentication. "
            "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks. "
            "Authentication weaknesses include: permits automated attacks such as credential stuffing, "
            "permits brute force or other automated attacks, permits default, weak, or well-known passwords such as 'Password1', "
            "uses weak or ineffective credential recovery, uses plain text, encrypted, or weakly hashed passwords, "
            "missing or ineffective multi-factor authentication, exposes session identifier in the URL, "
            "does not correctly invalidate session IDs after logout or a period of inactivity."
        ),
        "mitigations": (
            "Implement multi-factor authentication. "
            "Do not ship or deploy with any default credentials, especially for admin users. "
            "Implement weak password checks. "
            "Limit or delay failed login attempts — log failures and alert administrators. "
            "Use a server-side, secure, built-in session manager that generates a new random session ID with high entropy after login."
        ),
    },
    {
        "id": "A08:2021",
        "title": "Software and Data Integrity Failures",
        "cwe_ids": ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-915"],
        "description": (
            "A new category for 2021 focusing on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. "
            "Applications relying upon plugins, libraries, or modules from untrusted sources, repositories, and CDNs. "
            "Insecure deserialization: objects or data are encoded or serialized into a structure that an attacker can see and modify. "
            "Auto-update functionality that downloads updates without integrity verification. "
            "Libraries and dependencies from untrusted sources."
        ),
        "mitigations": (
            "Use digital signatures or similar mechanisms to verify that software or data is from the expected source and has not been altered. "
            "Ensure libraries and dependencies are consuming trusted repositories. "
            "Ensure there is a review process for code and configuration changes to minimize the chance of malicious code. "
            "Ensure your CI/CD pipeline has proper segregation, configuration, and access control. "
            "Do not send unsigned or unencrypted serialized data to untrusted clients."
        ),
    },
    {
        "id": "A09:2021",
        "title": "Security Logging and Monitoring Failures",
        "cwe_ids": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "description": (
            "Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, "
            "maintain persistence, pivot to more systems, and tamper, extract, or destroy data. "
            "Auditable events such as logins, failed logins, and high-value transactions are not logged. "
            "Warnings and errors generate no, inadequate, or unclear log messages. "
            "Logs of applications and APIs are not monitored for suspicious activity. "
            "Logs are only stored locally. "
            "The application is unable to detect, escalate, or alert for active attacks in real-time or near real-time."
        ),
        "mitigations": (
            "Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context. "
            "Ensure logs are generated in a format that log management solutions can easily consume. "
            "Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion. "
            "Establish or adopt an incident response and recovery plan."
        ),
    },
    {
        "id": "A10:2021",
        "title": "Server-Side Request Forgery (SSRF)",
        "cwe_ids": ["CWE-918"],
        "description": (
            "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. "
            "It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network ACL. "
            "SSRF can be used to probe internal services (metadata endpoints like http://169.254.169.254), bypass IP-based access controls, "
            "access internal resources not exposed to the public, enumerate internal network, and perform request forgery attacks."
        ),
        "mitigations": (
            "Sanitize and validate all client-supplied input data. "
            "Enforce the URL schema, port, and destination with a positive allow list. "
            "Do not send raw responses to clients. "
            "Disable HTTP redirections. "
            "Be aware of the URL consistency to avoid attacks such as DNS rebinding and time-of-check, time-of-use race conditions. "
            "Segment remote resource access functionality in separate networks to reduce impact of SSRF."
        ),
    },
]


def load_owasp_knowledge(force_reload: bool = False) -> int:
    """Embed OWASP Top 10 2021 entries into ChromaDB. Returns entry count."""
    collection = get_or_create_collection("owasp")
    if not force_reload and collection.count() > 0:
        logger.info("OWASP collection already has %d entries — skipping", collection.count())
        return collection.count()

    ids, documents, metadatas = [], [], []
    for entry in _OWASP_TOP10:
        doc = (
            f"{entry['id']}: {entry['title']}\n"
            f"Related CWEs: {', '.join(entry['cwe_ids'])}\n"
            f"Description: {entry['description']}\n"
            f"Mitigations: {entry['mitigations']}"
        )
        ids.append(entry["id"])
        documents.append(doc)
        metadatas.append({
            "source": "owasp",
            "owasp_id": entry["id"],
            "title": entry["title"],
            "cwe_ids": ",".join(entry["cwe_ids"]),
        })

    from postura.knowledge.embedder import upsert_documents
    upsert_documents(collection, ids, documents, metadatas)
    logger.info("OWASP knowledge base ready: %d entries", collection.count())
    return collection.count()
