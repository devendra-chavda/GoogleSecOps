"""Utility functions for Google SecOps connector."""

import os


def parse_cron_timeout(cron_expr: str = None) -> int:
    """Parse CRON expression to compute function timeout in seconds.

    Extracts the minute interval from a CRON expression and converts it to seconds,
    subtracting a 30-second buffer for safety margin.

    Args:
        cron_expr: CRON expression (e.g., "0 */10 * * * *")
                   If None, reads from Schedule environment variable

    Returns:
        Timeout in seconds as integer

    Examples:
        - "0 */10 * * * *" (every 10 minutes) → 570 seconds (10*60-30)
        - "0 */5 * * * *" (every 5 minutes) → 270 seconds (5*60-30)
        - "0 * * * * *" (every 1 minute) → 30 seconds (1*60-30)
        - Invalid/missing → 570 seconds (default)
    """
    if cron_expr is None:
        cron_expr = os.environ.get("Schedule", "0 */10 * * * *")

    try:
        parts = cron_expr.split()
        if len(parts) >= 2:
            minute_field = parts[1]  # e.g., "*/10"
            if minute_field.startswith("*/"):
                interval = int(minute_field[2:])
                timeout = (interval * 60) - 30
                return max(timeout, 30)  # Minimum 30 seconds
    except (IndexError, ValueError, AttributeError):
        pass

    return 570  # Default: 9.5 minutes (for 10-minute schedule)
