"""Correlation tokens and chain digests: determinism, domain separation."""

from __future__ import annotations

from sagp.audit.hashing import canonical_json, chain_digest, hmac_token, normalize_entity

KEY = b"test-pepper"


def test_hmac_token_is_deterministic() -> None:
    a = hmac_token(KEY, "EMAIL_ADDRESS", "Alice@Example.com")
    b = hmac_token(KEY, "EMAIL_ADDRESS", "alice@example.com ")
    assert a == b  # normalized: casefold + strip


def test_hmac_token_domain_separates_types() -> None:
    # Same string, different entity type -> different token.
    assert hmac_token(KEY, "PERSON", "4111111111111111") != hmac_token(
        KEY, "CREDIT_CARD", "4111111111111111"
    )


def test_hmac_token_key_separates() -> None:
    assert hmac_token(b"k1", "PERSON", "bob") != hmac_token(b"k2", "PERSON", "bob")


def test_card_normalization_ignores_separators() -> None:
    assert normalize_entity("CREDIT_CARD", "4111 1111 1111 1111") == "4111111111111111"
    assert hmac_token(KEY, "CREDIT_CARD", "4111-1111-1111-1111") == hmac_token(
        KEY, "CREDIT_CARD", "4111111111111111"
    )


def test_chain_digest_is_order_sensitive_and_deterministic() -> None:
    p1 = {"a": 1, "b": 2, "prev_hash": "0" * 64}
    assert chain_digest(p1) == chain_digest({"b": 2, "a": 1, "prev_hash": "0" * 64})
    assert chain_digest(p1) != chain_digest({"a": 1, "b": 3, "prev_hash": "0" * 64})


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
