import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.compliance import (
    AssessmentStatus,
    ComplianceAssessment,
    ComplianceFramework,
    ComplianceScoreSnapshot,
    ComplianceViolation,
    ControlMapping,
    ControlStatus,
    FrameworkCode,
    SchemaValidationResult,
    ViolationStatus,
)
from app.schemas.compliance import (
    AssessmentCreate,
    AssessmentRead,
    ComplianceOverview,
    ComplianceSummary,
    ControlCoverageRow,
    ControlMappingRead,
    ControlRead,
    FrameworkRead,
    FrameworkScore,
    GapRead,
    ScoreTrendPoint,
    ScoreTrendSeries,
    ScoreTrendsResponse,
    SchemaValidationRow,
    SchemaValidationSummary,
    ViolationRead,
)

# A "partial" control mapping counts as half-covered — it demonstrates some
# control implementation but not full attestation coverage.
_PARTIAL_WEIGHT = 0.5


async def _load_frameworks(db: AsyncSession) -> list[ComplianceFramework]:
    result = await db.execute(
        select(ComplianceFramework)
        .options(selectinload(ComplianceFramework.control_mappings))
        .order_by(ComplianceFramework.display_name)
    )
    return list(result.scalars().all())


async def _open_violation_counts(db: AsyncSession) -> dict:
    rows = (
        await db.execute(
            select(ComplianceViolation.framework_id, func.count())
            .where(ComplianceViolation.status == ViolationStatus.OPEN)
            .group_by(ComplianceViolation.framework_id)
        )
    ).all()
    return dict(rows)


def _framework_to_read(framework: ComplianceFramework, open_counts: dict) -> FrameworkRead:
    return FrameworkRead(
        id=framework.id,
        code=framework.code.value,
        display_name=framework.display_name,
        subtitle=framework.subtitle,
        description=framework.description,
        auditor=framework.auditor,
        certified=framework.certified,
        cert_expires_at=framework.cert_expires_at,
        score=framework.score,
        open_violation_count=open_counts.get(framework.id, 0),
        control_breakdown=[
            ControlMappingRead(
                control_domain=m.control_domain,
                control_description=m.control_description,
                control_code=m.control_code,
                status=m.status.value,
            )
            for m in framework.control_mappings
        ],
    )


def _build_control_coverage(frameworks: list[ComplianceFramework]) -> list[ControlCoverageRow]:
    by_domain: dict[str, dict[str, ControlMapping]] = defaultdict(dict)
    descriptions: dict[str, str] = {}
    for framework in frameworks:
        for mapping in framework.control_mappings:
            by_domain[mapping.control_domain][framework.code.value] = mapping
            descriptions[mapping.control_domain] = mapping.control_description

    rows: list[ControlCoverageRow] = []
    for domain, per_framework in sorted(by_domain.items()):
        applicable = [
            m for m in per_framework.values() if m.status != ControlStatus.NOT_APPLICABLE
        ]
        weighted = sum(
            1.0 if m.status == ControlStatus.MAPPED else _PARTIAL_WEIGHT
            for m in applicable
            if m.status in (ControlStatus.MAPPED, ControlStatus.PARTIAL)
        )
        coverage = round(weighted / len(applicable) * 100, 0) if applicable else 0.0
        rows.append(
            ControlCoverageRow(
                control_domain=domain,
                control_description=descriptions[domain],
                per_framework={
                    code: ControlMappingRead(
                        control_domain=m.control_domain,
                        control_description=m.control_description,
                        control_code=m.control_code,
                        status=m.status.value,
                    )
                    for code, m in per_framework.items()
                },
                coverage_percent=coverage,
            )
        )
    return rows


async def _violations(db: AsyncSession) -> list[ViolationRead]:
    result = await db.execute(
        select(ComplianceViolation)
        .options(selectinload(ComplianceViolation.framework))
        .order_by(ComplianceViolation.detected_at.desc())
        .limit(50)
    )
    violations = result.scalars().all()
    return [
        ViolationRead(
            id=v.id,
            framework_code=v.framework.code.value,
            severity=v.severity.value,
            status=v.status.value,
            control_reference=v.control_reference,
            title=v.title,
            description=v.description,
            detected_at=v.detected_at,
            resolved_at=v.resolved_at,
            resolution_note=v.resolution_note,
        )
        for v in violations
    ]


async def _schema_validation_summary(db: AsyncSession) -> SchemaValidationSummary:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    result = await db.execute(
        select(SchemaValidationResult)
        .where(SchemaValidationResult.validated_at >= since)
        .order_by(SchemaValidationResult.validated_at.desc())
    )
    results = result.scalars().all()
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failures = [r for r in results if not r.passed]
    pass_rate = round(passed / total * 100, 2) if total else 100.0

    return SchemaValidationSummary(
        total_today=total,
        pass_rate_percent=pass_rate,
        failure_count=len(failures),
        failures=[
            SchemaValidationRow(
                endpoint_path=f.endpoint_path,
                schema_ref=f.schema_ref,
                passed=f.passed,
                error_message=f.error_message,
                tenant_slug=f.tenant_slug,
                reference_id=f.reference_id,
                validated_at=f.validated_at,
            )
            for f in failures[:10]
        ],
    )


async def get_compliance_overview(db: AsyncSession) -> ComplianceOverview:
    frameworks = await _load_frameworks(db)
    open_counts = await _open_violation_counts(db)

    overall_score = (
        round(sum(f.score for f in frameworks) / len(frameworks), 1) if frameworks else 0.0
    )

    return ComplianceOverview(
        overall_score=overall_score,
        frameworks=[_framework_to_read(f, open_counts) for f in frameworks],
        control_coverage=_build_control_coverage(frameworks),
        violations=await _violations(db),
        schema_validation=await _schema_validation_summary(db),
    )


# --------------------------------------------------------------------------- #
# Frameworks
# --------------------------------------------------------------------------- #


async def _get_framework_orm(db: AsyncSession, framework_id: uuid.UUID) -> ComplianceFramework:
    result = await db.execute(
        select(ComplianceFramework)
        .options(selectinload(ComplianceFramework.control_mappings))
        .where(ComplianceFramework.id == framework_id)
    )
    framework = result.scalar_one_or_none()
    if framework is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Framework not found")
    return framework


async def list_frameworks(db: AsyncSession) -> list[FrameworkRead]:
    frameworks = await _load_frameworks(db)
    open_counts = await _open_violation_counts(db)
    return [_framework_to_read(f, open_counts) for f in frameworks]


async def get_framework(db: AsyncSession, framework_id: uuid.UUID) -> FrameworkRead:
    framework = await _get_framework_orm(db, framework_id)
    open_counts = await _open_violation_counts(db)
    return _framework_to_read(framework, open_counts)


# --------------------------------------------------------------------------- #
# Controls
# --------------------------------------------------------------------------- #


def _control_to_read(mapping: ControlMapping) -> ControlRead:
    return ControlRead(
        id=mapping.id,
        framework_id=mapping.framework_id,
        framework_code=mapping.framework.code.value,
        control_domain=mapping.control_domain,
        control_description=mapping.control_description,
        control_code=mapping.control_code,
        status=mapping.status.value,
    )


async def list_controls(
    db: AsyncSession,
    *,
    framework_code: FrameworkCode | None = None,
    control_status: ControlStatus | None = None,
) -> list[ControlRead]:
    query = (
        select(ControlMapping)
        .join(ControlMapping.framework)
        .options(selectinload(ControlMapping.framework))
        .order_by(ComplianceFramework.code, ControlMapping.control_domain)
    )
    if framework_code is not None:
        query = query.where(ComplianceFramework.code == framework_code)
    if control_status is not None:
        query = query.where(ControlMapping.status == control_status)
    result = await db.execute(query)
    return [_control_to_read(m) for m in result.scalars().all()]


async def get_control(db: AsyncSession, control_id: uuid.UUID) -> ControlRead:
    result = await db.execute(
        select(ControlMapping)
        .options(selectinload(ControlMapping.framework))
        .where(ControlMapping.id == control_id)
    )
    mapping = result.scalar_one_or_none()
    if mapping is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")
    return _control_to_read(mapping)


# --------------------------------------------------------------------------- #
# Summary & gaps
# --------------------------------------------------------------------------- #


async def get_compliance_summary(db: AsyncSession) -> ComplianceSummary:
    frameworks = await _load_frameworks(db)
    open_counts = await _open_violation_counts(db)

    total = mapped = partial = gap = 0
    for framework in frameworks:
        for mapping in framework.control_mappings:
            total += 1
            if mapping.status == ControlStatus.MAPPED:
                mapped += 1
            elif mapping.status == ControlStatus.PARTIAL:
                partial += 1
            elif mapping.status == ControlStatus.GAP:
                gap += 1

    overall_score = (
        round(sum(f.score for f in frameworks) / len(frameworks), 1) if frameworks else 0.0
    )

    return ComplianceSummary(
        overall_score=overall_score,
        framework_count=len(frameworks),
        certified_count=sum(1 for f in frameworks if f.certified),
        total_controls=total,
        mapped_controls=mapped,
        partial_controls=partial,
        gap_controls=gap,
        open_violation_count=sum(open_counts.values()),
        frameworks=[
            FrameworkScore(
                code=f.code.value,
                display_name=f.display_name,
                score=f.score,
                certified=f.certified,
                open_violation_count=open_counts.get(f.id, 0),
            )
            for f in frameworks
        ],
    )


async def get_gaps(
    db: AsyncSession, *, framework_code: FrameworkCode | None = None
) -> list[GapRead]:
    query = (
        select(ControlMapping)
        .join(ControlMapping.framework)
        .options(selectinload(ControlMapping.framework))
        .where(ControlMapping.status.in_([ControlStatus.GAP, ControlStatus.PARTIAL]))
        .order_by(ComplianceFramework.code, ControlMapping.control_domain)
    )
    if framework_code is not None:
        query = query.where(ComplianceFramework.code == framework_code)
    result = await db.execute(query)
    return [
        GapRead(
            framework_id=m.framework_id,
            framework_code=m.framework.code.value,
            control_domain=m.control_domain,
            control_description=m.control_description,
            control_code=m.control_code,
            status=m.status.value,
        )
        for m in result.scalars().all()
    ]


# --------------------------------------------------------------------------- #
# Assessments
# --------------------------------------------------------------------------- #


def _assessment_to_read(assessment: ComplianceAssessment) -> AssessmentRead:
    return AssessmentRead(
        id=assessment.id,
        framework_id=assessment.framework_id,
        framework_code=assessment.framework.code.value,
        status=assessment.status.value,
        started_by=assessment.started_by,
        started_at=assessment.started_at,
        completed_at=assessment.completed_at,
        score=assessment.score,
        total_controls=assessment.total_controls,
        mapped_controls=assessment.mapped_controls,
        gap_controls=assessment.gap_controls,
        notes=assessment.notes,
    )


async def _get_assessment_orm(
    db: AsyncSession, assessment_id: uuid.UUID
) -> ComplianceAssessment:
    result = await db.execute(
        select(ComplianceAssessment)
        .options(selectinload(ComplianceAssessment.framework))
        .where(ComplianceAssessment.id == assessment_id)
    )
    assessment = result.scalar_one_or_none()
    if assessment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")
    return assessment


async def start_assessment(
    db: AsyncSession, payload: AssessmentCreate, started_by: str
) -> AssessmentRead:
    await _get_framework_orm(db, payload.framework_id)  # 404 if framework is unknown
    assessment = ComplianceAssessment(
        id=uuid.uuid4(),
        framework_id=payload.framework_id,
        status=AssessmentStatus.IN_PROGRESS,
        started_by=started_by,
        started_at=datetime.now(timezone.utc),
    )
    db.add(assessment)
    await db.commit()
    return _assessment_to_read(await _get_assessment_orm(db, assessment.id))


async def list_assessments(
    db: AsyncSession,
    *,
    framework_id: uuid.UUID | None = None,
    assessment_status: AssessmentStatus | None = None,
) -> list[AssessmentRead]:
    query = (
        select(ComplianceAssessment)
        .options(selectinload(ComplianceAssessment.framework))
        .order_by(ComplianceAssessment.started_at.desc())
    )
    if framework_id is not None:
        query = query.where(ComplianceAssessment.framework_id == framework_id)
    if assessment_status is not None:
        query = query.where(ComplianceAssessment.status == assessment_status)
    result = await db.execute(query)
    return [_assessment_to_read(a) for a in result.scalars().all()]


async def get_assessment(db: AsyncSession, assessment_id: uuid.UUID) -> AssessmentRead:
    return _assessment_to_read(await _get_assessment_orm(db, assessment_id))


async def complete_assessment(db: AsyncSession, assessment_id: uuid.UUID) -> AssessmentRead:
    assessment = await _get_assessment_orm(db, assessment_id)
    if assessment.status == AssessmentStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Assessment already completed"
        )

    framework = await _get_framework_orm(db, assessment.framework_id)
    mappings = framework.control_mappings
    applicable = [m for m in mappings if m.status != ControlStatus.NOT_APPLICABLE]
    # Score mirrors the overview's coverage weighting (mapped = 1, partial = 0.5).
    weighted = sum(
        1.0 if m.status == ControlStatus.MAPPED else _PARTIAL_WEIGHT
        for m in applicable
        if m.status in (ControlStatus.MAPPED, ControlStatus.PARTIAL)
    )
    score = round(weighted / len(applicable) * 100, 1) if applicable else 0.0

    assessment.status = AssessmentStatus.COMPLETED
    assessment.completed_at = datetime.now(timezone.utc)
    assessment.total_controls = len(mappings)
    assessment.mapped_controls = sum(1 for m in mappings if m.status == ControlStatus.MAPPED)
    assessment.gap_controls = sum(1 for m in mappings if m.status == ControlStatus.GAP)
    assessment.score = score
    await db.commit()
    return _assessment_to_read(await _get_assessment_orm(db, assessment.id))


# --------------------------------------------------------------------------- #
# Score trends
# --------------------------------------------------------------------------- #


async def get_score_trends(
    db: AsyncSession, *, window_days: int = 30
) -> ScoreTrendsResponse:
    since = datetime.now(timezone.utc) - timedelta(days=window_days)
    result = await db.execute(
        select(ComplianceScoreSnapshot)
        .options(selectinload(ComplianceScoreSnapshot.framework))
        .where(ComplianceScoreSnapshot.captured_at >= since)
        .order_by(
            ComplianceScoreSnapshot.framework_id, ComplianceScoreSnapshot.captured_at
        )
    )
    snapshots = result.scalars().all()

    grouped: dict[uuid.UUID, list[ComplianceScoreSnapshot]] = defaultdict(list)
    for snapshot in snapshots:
        grouped[snapshot.framework_id].append(snapshot)

    series: list[ScoreTrendSeries] = []
    for framework_id, snaps in grouped.items():
        snaps.sort(key=lambda s: s.captured_at)
        framework = snaps[0].framework
        series.append(
            ScoreTrendSeries(
                framework_id=framework_id,
                code=framework.code.value,
                display_name=framework.display_name,
                current_score=snaps[-1].score,
                delta=round(snaps[-1].score - snaps[0].score, 1),
                points=[
                    ScoreTrendPoint(captured_at=s.captured_at, score=s.score) for s in snaps
                ],
            )
        )

    series.sort(key=lambda s: s.display_name)
    return ScoreTrendsResponse(window_days=window_days, series=series)
