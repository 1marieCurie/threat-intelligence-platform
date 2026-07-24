from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


def test_hash_is_deterministic() -> None:
    hasher = Sha256PayloadHasher()

    payload = {
        "id": "CVE-2026-0001",
        "score": 9.8,
    }

    first_hash = hasher.hash(payload)
    second_hash = hasher.hash(payload)

    assert first_hash == second_hash
    assert len(first_hash) == 64


def test_hash_is_independent_of_key_order() -> None:
    hasher = Sha256PayloadHasher()

    first_payload = {
        "id": "CVE-2026-0001",
        "score": 9.8,
    }

    second_payload = {
        "score": 9.8,
        "id": "CVE-2026-0001",
    }

    assert (
        hasher.hash(first_payload)
        == hasher.hash(second_payload)
    )


def test_hash_changes_when_payload_changes() -> None:
    hasher = Sha256PayloadHasher()

    first_payload = {
        "id": "CVE-2026-0001",
        "score": 9.8,
    }

    second_payload = {
        "id": "CVE-2026-0001",
        "score": 7.5,
    }

    assert (
        hasher.hash(first_payload)
        != hasher.hash(second_payload)
    )