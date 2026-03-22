from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def verify_db_state(
    *,
    db_session: AsyncSession,
    valid_fact_count: int,
    validation_error_count: int,
    analysis_job_id: Optional[str] = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "expected": {
            "valid_fact_count": valid_fact_count,
            "validation_error_count": validation_error_count,
        },
        "facts_table": {
            "exists": False,
            "row_count": None,
        },
        "validation_reports_table": {
            "exists": False,
            "row_count": None,
        },
        "analysis_job": {
            "checked": False,
            "current_step": None,
            "status": None,
        },
    }

    tables = await _list_tables(db_session)

    if "facts" in tables:
        result["facts_table"]["exists"] = True
        result["facts_table"]["row_count"] = await _scalar(
            db_session,
            "SELECT COUNT(*) FROM facts",
        )

    if "validation_reports" in tables:
        result["validation_reports_table"]["exists"] = True
        result["validation_reports_table"]["row_count"] = await _scalar(
            db_session,
            "SELECT COUNT(*) FROM validation_reports",
        )

    if analysis_job_id and "analysis_jobs" in tables:
        result["analysis_job"]["checked"] = True
        res = await db_session.execute(
            text("SELECT current_step, status FROM analysis_jobs WHERE id = :id"),
            {"id": analysis_job_id},
        )
        row = res.mappings().first()
        if row:
            result["analysis_job"]["current_step"] = row.get("current_step")
            result["analysis_job"]["status"] = row.get("status")

    return result


async def _list_tables(db_session: AsyncSession) -> set[str]:
    res = await db_session.execute(
        text(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            """
        )
    )
    rows = res.fetchall()
    return {r[0] for r in rows}


async def _scalar(db_session: AsyncSession, sql: str) -> int:
    res = await db_session.execute(text(sql))
    return int(res.scalar_one())