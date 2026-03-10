"""Triage feedback endpoints — human-in-the-loop accuracy tracking."""

import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, extract, case, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AnalystUser, CurrentUser
from src.models.intel import TriageFeedback
from src.models.threat import Alert
from src.storage.database import get_session

router = APIRouter(prefix="/feedback", tags=["feedback"])


# --- Schemas ---


class FeedbackCreate(BaseModel):
    alert_id: uuid.UUID
    corrected_category: str | None = None
    corrected_severity: str | None = None
    is_true_positive: bool
    feedback_notes: str | None = None


class FeedbackResponse(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    analyst_id: uuid.UUID
    original_category: str
    original_severity: str
    original_confidence: float
    corrected_category: str | None
    corrected_severity: str | None
    is_true_positive: bool
    feedback_notes: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CategoryAccuracy(BaseModel):
    category: str
    total: int
    correct: int
    accuracy: float


class ConfusionEntry(BaseModel):
    original_category: str
    corrected_category: str
    count: int


class WeeklyAccuracy(BaseModel):
    week_start: str
    total: int
    true_positives: int
    accuracy: float


class FeedbackStats(BaseModel):
    total_feedback: int
    true_positives: int
    false_positives: int
    true_positive_rate: float
    false_positive_rate: float
    category_accuracy: list[CategoryAccuracy]
    confusion_matrix: list[ConfusionEntry]
    weekly_trend: list[WeeklyAccuracy]


class FewShotExample(BaseModel):
    alert_title: str
    alert_summary: str
    original_category: str
    original_severity: str
    original_confidence: float
    is_true_positive: bool
    corrected_category: str | None
    corrected_severity: str | None
    feedback_notes: str | None


class FewShotExamples(BaseModel):
    true_positives: list[FewShotExample]
    false_positives: list[FewShotExample]
    corrections: list[FewShotExample]


# --- Routes ---


@router.post("/", response_model=FeedbackResponse, status_code=201)
async def submit_feedback(
    body: FeedbackCreate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_session),
):
    """Submit triage feedback on an alert."""
    # Load the alert to capture its current triage state
    alert = await db.get(Alert, body.alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    # Check for duplicate feedback from same analyst
    existing_q = select(TriageFeedback).where(
        TriageFeedback.alert_id == body.alert_id,
        TriageFeedback.analyst_id == user.id,
    )
    existing = (await db.execute(existing_q)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "You have already submitted feedback for this alert")

    feedback = TriageFeedback(
        alert_id=body.alert_id,
        analyst_id=user.id,
        original_category=alert.category,
        original_severity=alert.severity,
        original_confidence=alert.confidence,
        corrected_category=body.corrected_category,
        corrected_severity=body.corrected_severity,
        is_true_positive=body.is_true_positive,
        feedback_notes=body.feedback_notes,
    )
    db.add(feedback)
    await db.commit()
    await db.refresh(feedback)
    return feedback


@router.get("/", response_model=list[FeedbackResponse])
async def list_feedback(
    user: CurrentUser,
    alert_id: uuid.UUID | None = None,
    analyst_id: uuid.UUID | None = None,
    is_true_positive: bool | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
):
    """List all feedback entries with optional filters."""
    query = select(TriageFeedback).order_by(desc(TriageFeedback.created_at))

    if alert_id:
        query = query.where(TriageFeedback.alert_id == alert_id)
    if analyst_id:
        query = query.where(TriageFeedback.analyst_id == analyst_id)
    if is_true_positive is not None:
        query = query.where(TriageFeedback.is_true_positive == is_true_positive)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=FeedbackStats)
async def feedback_stats(
    user: CurrentUser,
    db: AsyncSession = Depends(get_session),
):
    """Compute real accuracy metrics from triage feedback."""
    # Total counts
    total = (await db.execute(
        select(func.count()).select_from(TriageFeedback)
    )).scalar() or 0

    if total == 0:
        return FeedbackStats(
            total_feedback=0,
            true_positives=0,
            false_positives=0,
            true_positive_rate=0.0,
            false_positive_rate=0.0,
            category_accuracy=[],
            confusion_matrix=[],
            weekly_trend=[],
        )

    tp_count = (await db.execute(
        select(func.count()).select_from(TriageFeedback).where(TriageFeedback.is_true_positive == True)
    )).scalar() or 0

    fp_count = total - tp_count

    # Per-category accuracy: correct means is_true_positive AND no category correction
    cat_q = (
        select(
            TriageFeedback.original_category,
            func.count().label("total"),
            func.sum(
                case(
                    (
                        and_(
                            TriageFeedback.is_true_positive == True,
                            TriageFeedback.corrected_category.is_(None),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("correct"),
        )
        .group_by(TriageFeedback.original_category)
    )
    cat_rows = (await db.execute(cat_q)).all()
    category_accuracy = [
        CategoryAccuracy(
            category=row[0],
            total=row[1],
            correct=int(row[2] or 0),
            accuracy=round(int(row[2] or 0) / row[1], 4) if row[1] > 0 else 0.0,
        )
        for row in cat_rows
    ]

    # Confusion matrix: original_category -> corrected_category counts (only where corrected)
    confusion_q = (
        select(
            TriageFeedback.original_category,
            TriageFeedback.corrected_category,
            func.count(),
        )
        .where(TriageFeedback.corrected_category.isnot(None))
        .group_by(TriageFeedback.original_category, TriageFeedback.corrected_category)
        .order_by(func.count().desc())
    )
    confusion_rows = (await db.execute(confusion_q)).all()
    confusion_matrix = [
        ConfusionEntry(
            original_category=row[0],
            corrected_category=row[1],
            count=row[2],
        )
        for row in confusion_rows
    ]

    # Weekly accuracy trend (last 12 weeks)
    twelve_weeks_ago = datetime.now(timezone.utc) - timedelta(weeks=12)
    weekly_q = (
        select(
            func.date_trunc("week", TriageFeedback.created_at).label("week_start"),
            func.count().label("total"),
            func.sum(
                case(
                    (TriageFeedback.is_true_positive == True, 1),
                    else_=0,
                )
            ).label("tp"),
        )
        .where(TriageFeedback.created_at >= twelve_weeks_ago)
        .group_by(func.date_trunc("week", TriageFeedback.created_at))
        .order_by(func.date_trunc("week", TriageFeedback.created_at))
    )
    weekly_rows = (await db.execute(weekly_q)).all()
    weekly_trend = [
        WeeklyAccuracy(
            week_start=row[0].strftime("%Y-%m-%d") if row[0] else "",
            total=row[1],
            true_positives=int(row[2] or 0),
            accuracy=round(int(row[2] or 0) / row[1], 4) if row[1] > 0 else 0.0,
        )
        for row in weekly_rows
    ]

    return FeedbackStats(
        total_feedback=total,
        true_positives=tp_count,
        false_positives=fp_count,
        true_positive_rate=round(tp_count / total, 4),
        false_positive_rate=round(fp_count / total, 4),
        category_accuracy=category_accuracy,
        confusion_matrix=confusion_matrix,
        weekly_trend=weekly_trend,
    )


@router.get("/examples", response_model=FewShotExamples)
async def feedback_examples(
    user: CurrentUser,
    limit: int = Query(5, le=20),
    db: AsyncSession = Depends(get_session),
):
    """Get recent correct and incorrect examples formatted for LLM few-shot prompting."""
    # True positive examples (correctly classified, no correction needed)
    tp_q = (
        select(TriageFeedback, Alert)
        .join(Alert, TriageFeedback.alert_id == Alert.id)
        .where(
            TriageFeedback.is_true_positive == True,
            TriageFeedback.corrected_category.is_(None),
        )
        .order_by(desc(TriageFeedback.created_at))
        .limit(limit)
    )
    tp_rows = (await db.execute(tp_q)).all()
    true_positives = [
        FewShotExample(
            alert_title=alert.title,
            alert_summary=alert.summary,
            original_category=fb.original_category,
            original_severity=fb.original_severity,
            original_confidence=fb.original_confidence,
            is_true_positive=True,
            corrected_category=None,
            corrected_severity=None,
            feedback_notes=fb.feedback_notes,
        )
        for fb, alert in tp_rows
    ]

    # False positive examples
    fp_q = (
        select(TriageFeedback, Alert)
        .join(Alert, TriageFeedback.alert_id == Alert.id)
        .where(TriageFeedback.is_true_positive == False)
        .order_by(desc(TriageFeedback.created_at))
        .limit(limit)
    )
    fp_rows = (await db.execute(fp_q)).all()
    false_positives = [
        FewShotExample(
            alert_title=alert.title,
            alert_summary=alert.summary,
            original_category=fb.original_category,
            original_severity=fb.original_severity,
            original_confidence=fb.original_confidence,
            is_true_positive=False,
            corrected_category=fb.corrected_category,
            corrected_severity=fb.corrected_severity,
            feedback_notes=fb.feedback_notes,
        )
        for fb, alert in fp_rows
    ]

    # Correction examples (true positive but category/severity was wrong)
    correction_q = (
        select(TriageFeedback, Alert)
        .join(Alert, TriageFeedback.alert_id == Alert.id)
        .where(
            TriageFeedback.is_true_positive == True,
            TriageFeedback.corrected_category.isnot(None),
        )
        .order_by(desc(TriageFeedback.created_at))
        .limit(limit)
    )
    correction_rows = (await db.execute(correction_q)).all()
    corrections = [
        FewShotExample(
            alert_title=alert.title,
            alert_summary=alert.summary,
            original_category=fb.original_category,
            original_severity=fb.original_severity,
            original_confidence=fb.original_confidence,
            is_true_positive=True,
            corrected_category=fb.corrected_category,
            corrected_severity=fb.corrected_severity,
            feedback_notes=fb.feedback_notes,
        )
        for fb, alert in correction_rows
    ]

    return FewShotExamples(
        true_positives=true_positives,
        false_positives=false_positives,
        corrections=corrections,
    )
