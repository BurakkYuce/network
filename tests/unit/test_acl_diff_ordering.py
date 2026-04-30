"""ACL sequence-aware diff tests.

Verifies that the dict-by-seq projection preserves the *identity* of ACL
entries by their sequence number — so diffs are stable under insertions,
deletions and reordering elsewhere in the list.
"""

from datetime import UTC, datetime

from netauto.state.diff import diff_states
from netauto.state.models.v1 import ACL, ACLEntry, DeviceStateV1


def _state_with_acl(*entries: ACLEntry, name: str = "EDGE-IN") -> DeviceStateV1:
    return DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime(2026, 4, 30, 13, 0, tzinfo=UTC),
        acls={name: ACL(name=name, entries=list(entries))},
    )


def _entry(seq: int, action: str = "permit", **kw: str) -> ACLEntry:
    base = {"src": "any", "dst": "any", "proto": "ip"}
    base.update(kw)
    return ACLEntry(seq=seq, action=action, **base)  # type: ignore[arg-type]


def test_acl_permit_any_any_inserted_at_top() -> None:
    """T1562.004 archetype: attacker inserts permit ip any any at seq 5."""
    old = _state_with_acl(_entry(10, proto="tcp", dst_port="22"), _entry(20, action="deny"))
    new = _state_with_acl(
        _entry(5, action="permit", proto="ip"),  # the attack
        _entry(10, proto="tcp", dst_port="22"),
        _entry(20, action="deny"),
    )
    result = diff_states(old, new)
    add_ops = [op for op in result.ops if op["op"] == "add"]
    assert len(add_ops) == 1
    assert add_ops[0]["path"] == "/acls/EDGE-IN/entries/5"
    assert add_ops[0]["value"]["action"] == "permit"
    assert add_ops[0]["value"]["proto"] == "ip"


def test_acl_entry_removed_keeps_others_stable() -> None:
    """Removing seq 20 should produce ONE remove op, not a cascade."""
    old = _state_with_acl(_entry(10), _entry(20), _entry(30))
    new = _state_with_acl(_entry(10), _entry(30))
    result = diff_states(old, new)
    remove_ops = [op for op in result.ops if op["op"] == "remove"]
    assert len(remove_ops) == 1
    assert remove_ops[0]["path"] == "/acls/EDGE-IN/entries/20"


def test_acl_entry_modified_in_place() -> None:
    """Changing seq 20 from deny to permit should produce a replace at /20."""
    old = _state_with_acl(_entry(10), _entry(20, action="deny"))
    new = _state_with_acl(_entry(10), _entry(20, action="permit"))
    result = diff_states(old, new)
    replace_ops = [op for op in result.ops if op["op"] == "replace"]
    assert len(replace_ops) == 1
    assert "/acls/EDGE-IN/entries/20/action" in replace_ops[0]["path"]
    assert replace_ops[0]["value"] == "permit"


def test_acl_entry_moved_via_renumber() -> None:
    """Renumbering seq 30 to seq 5 surfaces both seq numbers in ops or `from`.

    jsonpatch may emit either remove(/30)+add(/5) or move(from=/30, path=/5).
    Either is acceptable; downstream detection correlates by seq identity.
    """
    old = _state_with_acl(_entry(10), _entry(20), _entry(30, action="permit", proto="ip"))
    new = _state_with_acl(
        _entry(5, action="permit", proto="ip"),  # was 30
        _entry(10),
        _entry(20),
    )
    result = diff_states(old, new)
    locations: set[str] = set()
    for op in result.ops:
        locations.add(op["path"])
        if "from" in op:
            locations.add(op["from"])
    assert "/acls/EDGE-IN/entries/30" in locations
    assert "/acls/EDGE-IN/entries/5" in locations


def test_acl_unchanged_produces_no_drift() -> None:
    state = _state_with_acl(_entry(10), _entry(20, action="deny"))
    result = diff_states(state, state)
    assert result.is_empty


def test_acl_added_to_device() -> None:
    old = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime(2026, 4, 30, tzinfo=UTC),
    )
    new = _state_with_acl(_entry(10), name="MGMT-IN")
    result = diff_states(old, new)
    add_ops = [op for op in result.ops if op["op"] == "add" and op["path"] == "/acls/MGMT-IN"]
    assert len(add_ops) == 1


def test_acl_unbound_from_interface_via_diff() -> None:
    """T1562.004 archetype 2: removing acl_in from an interface yields a remove."""
    from netauto.state.models.v1 import Interface

    old = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime(2026, 4, 30, tzinfo=UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0", acl_in="EDGE-IN")},
    )
    new = DeviceStateV1(
        hostname="r1",
        platform="ios-xe",
        captured_at=datetime(2026, 4, 30, tzinfo=UTC),
        interfaces={"Gi0/0": Interface(name="Gi0/0", acl_in=None)},
    )
    result = diff_states(old, new)
    # acl_in becomes null, that's a replace from "EDGE-IN" -> null
    replace_ops = [
        op for op in result.ops if op["op"] == "replace" and op["path"].endswith("/acl_in")
    ]
    assert len(replace_ops) == 1
    assert replace_ops[0]["value"] is None
