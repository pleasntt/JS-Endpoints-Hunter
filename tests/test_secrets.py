from __future__ import annotations

from jsh.extractors import extract_all
from jsh.extractors.secrets import extract_secrets


def test_aws_key_is_masked_and_raw_is_opt_in(patterns):
    findings = extract_secrets(
        'const key = "AKIAABCDEFGHIJKLMNOP";',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    assert len(findings) == 1
    item = findings[0]
    assert item.secret_type == "aws_access_key"
    assert item.masked == "AKIA****************"
    public = item.to_dict(show_secrets=False)
    assert public["value"] == "AKIA****************"
    assert public["raw"] == ""
    assert "AKIAABCDEFGHIJKLMNOP" not in public["snippet"]
    assert item.to_dict(show_secrets=True)["raw"] == "AKIAABCDEFGHIJKLMNOP"


def test_stripe_and_github_tokens(patterns):
    findings = extract_secrets(
        f'stripe="{"sk_test_"}{"0" * 24}"; github="{"ghp_"}{"a" * 36}";',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    types = {item.secret_type for item in findings}
    assert "stripe_key" in types
    assert "github_token" in types
    assert all(item.masked != item.raw for item in findings)


def test_jwt_decode_without_signature_verification(patterns):
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"
    findings = extract_secrets(
        f'const token = "{token}";',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    jwt = next(item for item in findings if item.secret_type == "jwt")
    assert jwt.meta["jwt"]["header"]["alg"] == "HS256"
    assert jwt.meta["jwt"]["payload"]["sub"] == "test"
    assert "jwt" not in jwt.to_dict(show_secrets=False)["meta"]


def test_private_key(patterns):
    key = "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATA\n-----END RSA PRIVATE KEY-----"
    findings = extract_secrets(key, "", "key.pem", "minified", patterns)
    item = next(item for item in findings if item.secret_type == "private_key")
    assert "REDACTED" in item.masked
    assert "FAKEKEYDATA" not in item.masked


def test_generic_secret_low_severity(patterns):
    findings = extract_all(
        'const api_key = "abcdefghijklmnop";',
        "https://example.com/app.js",
        "app.js",
        "minified",
        patterns,
    )
    generic = [item for item in findings if item.secret_type == "generic_secret"]
    assert generic
    assert generic[0].severity == "LOW"
