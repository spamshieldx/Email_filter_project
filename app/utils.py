from typing import List, Optional, Tuple, Dict, Any
from flask import current_app
import re

# Simple helpers used across routes and services

def safe_get_str(value: Any) -> str:
    """Return a safe string for incoming values."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)

def normalize_sender(sender: str) -> str:
    """Strip and lower the sender value (extract email if 'Name <email@host>')."""
    s = safe_get_str(sender).strip()
    # attempt to extract <...>
    m = re.search(r"<([^>]+)>", s)
    if m:
        return m.group(1).lower()
    return s.lower()

def paginate_list(items: List[Any], page: int, page_size: int) -> Tuple[List[Any], Dict[str, int]]:
    """
    Return a slice of items and pagination metadata.
    page: 1-based page index
    """
    try:
        page = max(int(page), 1)
    except Exception:
        page = 1
    try:
        page_size = max(int(page_size), 1)
    except Exception:
        page_size = 20

    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]
    meta = {"page": page, "page_size": page_size, "total": total, "pages": (total + page_size - 1) // page_size}
    return page_items, meta

def extract_header_value(headers: Optional[List[dict]], header_name: str) -> Optional[str]:
    """Return first header value for a given header name."""
    if not headers:
        return None
    for h in headers:
        if not isinstance(h, dict):
            continue
        if (h.get('name') or "").lower() == header_name.lower():
            return h.get('value')
    return None
