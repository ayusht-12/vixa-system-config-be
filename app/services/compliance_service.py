from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.compliance import (
    ComplianceFramework,
    ComplianceViolation,
    ControlMapping,
    ControlStatus,
    SchemaValidationResult,
    ViolationStatus,
)
from app.schemas.compliance import (
    ComplianceOverview,
    ControlCoverageRow,
    ControlMappingRead,
    FrameworkRead,
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
