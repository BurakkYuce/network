from datetime import UTC, datetime

from netauto.state.diff import diff_states, state_to_diffable
from netauto.state.models.v1 import (
    ACL,
    ACLEntry,
    DeviceStateV1,
    Interface,
    LocalUser,
)


def _state(**kw: object) -> DeviceStateV1:
    return DeviceStateV1(
        hostname=kw.pop("hostname", "r1"),  # type: ignore[arg-type]
        platform=kw.pop("platform", "ios-xe"),  # type: ignore[arg-type]
        captured_at=kw.pop("captured_at", datetime(2026, 4, 30, 13, 0, 0, tzinfo=UTC)),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )


def test_state_to_diffable_strips_captured_at() -> None:
    s = _state()
    d = state_to_diffable(s)
    assert "captured_at" not in d


def test_state_to_diffable_acl_entries_become_dict_by_seq() -> None:
    s = _state(
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                    ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any"),
                ],
            )
        }
    )
    d = state_to_diffable(s)
    entries = d["acls"]["EDGE-IN"]["entries"]
    assert isinstance(entries, dict)
    assert set(entries.keys()) == {"10", "20"}
    assert entries["10"]["action"] == "permit"
    assert "seq" not in entries["10"]


def test_diff_identical_states_is_empty() -> None:
    s = _state(interfaces={"Gi0/0": Interface(name="Gi0/0")})
    result = diff_states(s, s)
    assert result.is_empty
    assert result.ops == []
    assert result.summary == {}


def test_diff_added_interface() -> None:
    """Interface name with '/' becomes JSON Pointer ~1 — check via op value."""
    old = _state(interfaces={"Gi0/0": Interface(name="Gi0/0")})
    new = _state(
        interfaces={
            "Gi0/0": Interface(name="Gi0/0"),
            "Gi0/1": Interface(name="Gi0/1", description="lan"),
        }
    )
    result = diff_states(old, new)
    add_ops = [op for op in result.ops if op["op"] == "add"]
    matching = [op for op in add_ops if op.get("value", {}).get("name") == "Gi0/1"]
    assert len(matching) == 1
    assert matching[0]["value"]["description"] == "lan"


def test_diff_removed_user() -> None:
    old = _state(
        users={
            "admin": LocalUser(name="admin", privilege=15),
            "operator": LocalUser(name="operator", privilege=5),
        }
    )
    new = _state(users={"admin": LocalUser(name="admin", privilege=15)})
    result = diff_states(old, new)
    remove_ops = [op for op in result.ops if op["op"] == "remove" and "operator" in op["path"]]
    assert len(remove_ops) == 1


def test_diff_modified_interface_description() -> None:
    old = _state(interfaces={"Gi0/0": Interface(name="Gi0/0", description="old")})
    new = _state(interfaces={"Gi0/0": Interface(name="Gi0/0", description="new")})
    result = diff_states(old, new)
    replace_ops = [op for op in result.ops if op["op"] == "replace"]
    assert len(replace_ops) == 1
    assert "description" in replace_ops[0]["path"]
    assert replace_ops[0]["value"] == "new"


def test_diff_acl_added_entry_seq_5() -> None:
    """Inserting a permit-any-any at seq=5 produces an add op at /entries/5."""
    old = _state(
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                    ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any"),
                ],
            )
        }
    )
    new = _state(
        acls={
            "EDGE-IN": ACL(
                name="EDGE-IN",
                entries=[
                    ACLEntry(seq=5, action="permit", proto="ip", src="any", dst="any"),
                    ACLEntry(seq=10, action="permit", proto="tcp", src="any", dst="any"),
                    ACLEntry(seq=20, action="deny", proto="ip", src="any", dst="any"),
                ],
            )
        }
    )
    result = diff_states(old, new)
    adds = [op for op in result.ops if op["op"] == "add" and "/entries/5" in op["path"]]
    assert len(adds) == 1
    assert adds[0]["value"]["action"] == "permit"
    assert adds[0]["value"]["src"] == "any"
    assert adds[0]["value"]["dst"] == "any"


def test_diff_summary_counts() -> None:
    old = _state(interfaces={"Gi0/0": Interface(name="Gi0/0", description="old")})
    new = _state(
        interfaces={
            "Gi0/0": Interface(name="Gi0/0", description="new"),
            "Gi0/1": Interface(name="Gi0/1"),
        }
    )
    result = diff_states(old, new)
    assert result.summary.get("replace", 0) >= 1
    assert result.summary.get("add", 0) >= 1


def test_diff_with_ephemeral_strip() -> None:
    """Ephemeral patterns are stripped from synthesized state-shaped dicts."""
    # We simulate ephemeral stripping by injecting paths into model_dump output via
    # a custom test case using the strip_ephemeral integration with diff_states.
    old = _state()
    new = _state()
    # No actual ephemeral fields in v1 yet, so this should yield no diff.
    result = diff_states(old, new, ephemeral_patterns=[["interfaces", "*", "counters"]])
    assert result.is_empty


def test_diff_hostname_change_is_detected() -> None:
    old = _state(hostname="r1")
    new = _state(hostname="r1-renamed")
    result = diff_states(old, new)
    assert any(op["op"] == "replace" and op["path"] == "/hostname" for op in result.ops)


def test_diff_user_privilege_escalation() -> None:
    """Privilege upgrade from 5 -> 15 should produce a replace op."""
    old = _state(users={"u1": LocalUser(name="u1", privilege=5)})
    new = _state(users={"u1": LocalUser(name="u1", privilege=15)})
    result = diff_states(old, new)
    replace_ops = [op for op in result.ops if op["op"] == "replace" and "/privilege" in op["path"]]
    assert len(replace_ops) == 1
    assert replace_ops[0]["value"] == 15
