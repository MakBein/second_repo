from xss_security_gui.utils.collections import dedupe_preserve_order


def test_dedupe_preserves_order_for_hashable_values():
    assert dedupe_preserve_order(["a", "b", "a", 1, 1]) == ["a", "b", 1]


def test_dedupe_handles_json_serializable_containers():
    first = {"name": "page", "values": [1, 2]}
    duplicate = {"values": [1, 2], "name": "page"}

    assert dedupe_preserve_order([first, duplicate, {"name": "other"}]) == [
        first,
        {"name": "other"},
    ]


def test_dedupe_handles_tuples_containing_unhashable_values():
    assert dedupe_preserve_order([([1, 2],), ([1, 2],), ([3],)]) == [
        ([1, 2],),
        ([3],),
    ]
