"""Every plugin here conforms to the class contract (plugin API 2.1): liminal_libs.sources.conformance, read
from the plugin alone (nothing runs)."""
from __future__ import annotations

import plugin_platform_hw_stats as module
from liminal_libs.sources.conformance import assert_module_conforms


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert found and all(p.api == "2.1" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    assert {p.ICON for p in found} == {"gauge"}
