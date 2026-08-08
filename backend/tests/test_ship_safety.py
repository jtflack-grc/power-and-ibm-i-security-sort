from app.main import _safe_dist_file, FRONTEND_DIST
from app.scoring.guidance import _is_allowed_bulletin_fetch


def test_bulletin_fetch_allows_ibm_only():
    assert _is_allowed_bulletin_fetch("https://www.ibm.com/support/pages/node/1")
    assert _is_allowed_bulletin_fetch("https://www.ibm.com/support/fixcentral")
    assert not _is_allowed_bulletin_fetch("https://evil.example/steal")
    assert not _is_allowed_bulletin_fetch("file:///etc/passwd")
    assert not _is_allowed_bulletin_fetch("http://127.0.0.1:8000/admin")
    assert not _is_allowed_bulletin_fetch("https://ibm.com.evil.example/")


def test_spa_path_escape_rejected(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text("<html></html>", encoding="utf-8")
    (assets / "ok.js").write_text("1", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("nope", encoding="utf-8")

    monkeypatch.setattr("app.main.FRONTEND_DIST", dist)
    # Re-import helper bound to patched path via redefining using module function
    from app import main as main_mod

    monkeypatch.setattr(main_mod, "FRONTEND_DIST", dist)

    assert main_mod._safe_dist_file("assets/ok.js") is not None
    assert main_mod._safe_dist_file("../secret.txt") is None
    assert main_mod._safe_dist_file("..\\secret.txt") is None
    assert FRONTEND_DIST  # module still imports
