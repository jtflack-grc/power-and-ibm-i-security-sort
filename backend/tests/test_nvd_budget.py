from app.collectors.nvd import (
    PLATFORM_QUERIES_FULL,
    PLATFORM_QUERIES_SLIM,
    _publication_windows,
    count_nvd_queries,
)


def test_slim_recipe_is_much_smaller_than_full():
    slim = count_nvd_queries(slim=True)
    full = count_nvd_queries(slim=False)
    assert slim == sum(
        len(r.get("virtual_matches") or []) + len(r.get("keywords") or [])
        for r in PLATFORM_QUERIES_SLIM.values()
    )
    assert full == sum(
        len(r.get("virtual_matches") or []) + len(r.get("keywords") or [])
        for r in PLATFORM_QUERIES_FULL.values()
    )
    assert slim <= 8
    assert full > slim


def test_nvd_publication_windows_respect_api_limit():
    windows = _publication_windows(400)
    assert len(windows) == 4
    assert all(start < end for start, end in windows)
