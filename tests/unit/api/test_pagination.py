import pytest
from cactus_schema.orchestrator import Pagination

from cactus_orchestrator.api.pagination import PageParams, build_page, paginate_sequence


@pytest.mark.parametrize(
    "page, size, expected_offset",
    [(1, 50, 0), (2, 50, 50), (3, 10, 20), (1, 1, 0), (5, 1, 4)],
)
def test_page_params_offset_limit(page: int, size: int, expected_offset: int):
    params = PageParams(page=page, size=size)
    assert params.offset == expected_offset
    assert params.limit == size


@pytest.mark.parametrize(
    "page, size, total, expected_total_pages, expected_prev, expected_next",
    [
        (1, 50, 0, 0, None, None),  # Empty
        (1, 50, 1, 1, None, None),  # Single partial page
        (1, 10, 10, 1, None, None),  # Exactly one full page
        (1, 10, 11, 2, None, 2),  # First of two
        (2, 10, 11, 2, 1, None),  # Last of two
        (2, 10, 30, 3, 1, 3),  # Middle page
        (5, 10, 11, 2, 4, None),  # Past the end
    ],
)
def test_build_page(
    page: int,
    size: int,
    total: int,
    expected_total_pages: int,
    expected_prev: int | None,
    expected_next: int | None,
):
    items = ["a", "b"]
    result = build_page(items, total, PageParams(page=page, size=size))

    assert isinstance(result, Pagination)
    assert result.items == items
    assert result.total_items == total
    assert result.total_pages == expected_total_pages
    assert result.page_size == size
    assert result.current_page == page
    assert result.prev_page == expected_prev
    assert result.next_page == expected_next


@pytest.mark.parametrize(
    "page, size, expected_items",
    [
        (1, 50, list(range(7))),
        (1, 3, [0, 1, 2]),
        (2, 3, [3, 4, 5]),
        (3, 3, [6]),
        (4, 3, []),
    ],
)
def test_paginate_sequence(page: int, size: int, expected_items: list[int]):
    result = paginate_sequence(list(range(7)), PageParams(page=page, size=size))
    assert result.items == expected_items
    assert result.total_items == 7
