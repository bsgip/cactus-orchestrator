from collections.abc import Sequence
from dataclasses import dataclass
from math import ceil

from cactus_schema.orchestrator import Pagination
from fastapi import Query

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


@dataclass(frozen=True)
class PageParams:
    """Pagination query parameters for list endpoints. Inject with Annotated[PageParams, Depends()]"""

    page: int = Query(default=1, ge=1, description="Page number (1-based)")
    size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Page size")

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size

    @property
    def limit(self) -> int:
        return self.size


def build_page[T](items: Sequence[T], total_items: int, params: PageParams) -> Pagination[T]:
    """Wraps a single page of items (already offset/limited by the caller) into a Pagination response.

    total_items should be the count of ALL items across every page."""
    total_pages = ceil(total_items / params.size)
    return Pagination(
        total_pages=total_pages,
        total_items=total_items,
        page_size=params.size,
        current_page=params.page,
        prev_page=params.page - 1 if params.page > 1 else None,
        next_page=params.page + 1 if params.page < total_pages else None,
        items=list(items),
    )


def paginate_sequence[T](items: Sequence[T], params: PageParams) -> Pagination[T]:
    """Paginates an in-memory sequence. Only intended for small, static lists that don't come from the database."""
    return build_page(items[params.offset : params.offset + params.limit], len(items), params)
