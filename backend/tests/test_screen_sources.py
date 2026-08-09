"""Integrity checks for the PTF terminal provenance registry."""

import json
from pathlib import Path


REGISTRY = (
    Path(__file__).resolve().parents[2]
    / "frontend"
    / "public"
    / "ironterm"
    / "fixtures"
    / "screen-sources.json"
)
IRONTERM_ROOT = REGISTRY.parent.parent
FRONTEND_ROOT = REGISTRY.parents[3]


def test_ptf_screen_registry_has_source_gates():
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    screens = {screen["id"]: screen for screen in data["screens"]}
    assert {
        "WRKPTFGRP",
        "DSPPTFGRP",
        "DSPPTF_STATUS",
        "DSPPTF_DETAILS_MENU",
        "DSPPTF_GENERAL_INFORMATION",
    } <= screens.keys()

    for screen in screens.values():
        assert screen["remainingGate"]
        assert any(source["tier"] == "A" for source in screen["sources"])
        assert all(source["url"].startswith("https://") for source in screen["sources"])
        if screen["fixtureStatus"] == "enabled":
            assert screen["validation"]

    assert screens["DSPPTF_STATUS"]["fixtureStatus"] == "enabled"
    assert all(
        screens[screen_id]["fixtureStatus"] != "enabled"
        for screen_id in screens
        if screen_id != "DSPPTF_STATUS"
    )


def test_lcl_sources_are_commit_pinned():
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    commit = data["legacyControlLab"]["commit"]
    assert len(commit) == 40
    for screen in data["screens"]:
        for source in screen["sources"]:
            if source["tier"] == "B":
                assert commit in source["url"]


def test_scenario_message_boundary_rejects_caller_records():
    scenario = (IRONTERM_ROOT / "scenario-main.js").read_text(encoding="utf-8")
    rail = (
        FRONTEND_ROOT / "src" / "app" / "VerificationRail.tsx"
    ).read_text(encoding="utf-8")

    assert "message.records" not in scenario
    assert 'message.scenario !== DSPPTF_STATUS' in scenario
    assert "event.source !== window.parent" in scenario
    assert "event.source === frameRef.current?.contentWindow" in rail
    assert "channelToken" in scenario and "channelToken" in rail
    assert "MAX_RECORD_BYTES" in scenario and "MAX_RECORDS" in scenario


def test_scenario_browser_hardening_is_present():
    terminal_html = (IRONTERM_ROOT / "index.html").read_text(encoding="utf-8")
    app_html = FRONTEND_ROOT.joinpath("index.html").read_text(encoding="utf-8")
    scenario = (IRONTERM_ROOT / "scenario-main.js").read_text(encoding="utf-8")

    for html in (terminal_html, app_html):
        assert "Content-Security-Policy" in html
        assert "object-src 'none'" in html
        assert "form-action 'none'" in html
        assert "fonts.googleapis.com" not in html
        assert "fonts.gstatic.com" not in html
    assert 'allowClipboardPaste: false' in scenario
    assert 'location.hostname === "localhost"' in scenario
