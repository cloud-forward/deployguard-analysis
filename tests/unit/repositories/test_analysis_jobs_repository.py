import uuid
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.gateway.db.base import Base
from app.gateway.models import (
    AnalysisJob,
    AttackPath,
    AttackPathEdge,
    GraphEdge,
    GraphSnapshot,
    RemediationRecommendation,
)
from app.gateway.repositories.analysis_jobs_sqlalchemy import SqlAlchemyAnalysisJobRepository
from src.facts.canonical_fact import Fact


@pytest.fixture
async def repo_and_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        yield SqlAlchemyAnalysisJobRepository(session), session

    await engine.dispose()


class TestSqlAlchemyAnalysisJobRepository:
    def test_analysis_job_graph_id_has_graph_snapshots_fk(self):
        foreign_keys = {fk.target_fullname for fk in AnalysisJob.__table__.c.graph_id.foreign_keys}
        assert foreign_keys == {"graph_snapshots.id"}

    def test_graph_snapshot_has_required_cluster_fk(self):
        foreign_keys = {fk.target_fullname for fk in GraphSnapshot.__table__.c.cluster_id.foreign_keys}
        assert foreign_keys == {"clusters.id"}
        assert GraphSnapshot.__table__.c.cluster_id.nullable is False
        assert "k8s_scan_id" in GraphSnapshot.__table__.c
        assert "aws_scan_id" in GraphSnapshot.__table__.c
        assert "image_scan_id" in GraphSnapshot.__table__.c
        assert "status" in GraphSnapshot.__table__.c
        assert "node_count" in GraphSnapshot.__table__.c
        assert "edge_count" in GraphSnapshot.__table__.c
        assert "entry_point_count" in GraphSnapshot.__table__.c
        assert "crown_jewel_count" in GraphSnapshot.__table__.c
        assert "completed_at" in GraphSnapshot.__table__.c

    def test_attack_path_edges_matches_real_schema_without_graph_id(self):
        columns = AttackPathEdge.__table__.c
        assert "graph_id" not in columns
        assert "edge_id" not in columns
        assert "id" in columns
        assert "sequence" in columns
        assert columns.path_id.nullable is False
        foreign_keys = {fk.target_fullname for fk in columns.path_id.foreign_keys}
        assert foreign_keys == {"attack_paths.id"}

    def test_attack_paths_does_not_assume_title_column(self):
        columns = AttackPath.__table__.c
        assert "id" in columns
        assert "path_id" in columns
        assert "title" not in columns
        assert "edge_ids" not in columns

    def test_graph_edges_uses_id_not_edge_id(self):
        columns = GraphEdge.__table__.c
        assert "id" in columns
        assert "edge_id" not in columns
        assert "graph_id" in columns
        assert "source_node_id" in columns
        assert "target_node_id" in columns
        assert "source" not in columns
        assert "target" not in columns

    @pytest.mark.asyncio
    async def test_create_analysis_job_persists_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id_from_scan_record = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id_from_scan_record,
            k8s_scan_id="20260309T113020-k8s",
            aws_scan_id="20260309T113020-aws",
            image_scan_id="20260309T113020-image",
            expected_scans=["k8s", "aws", "image"],
        )

        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        assert job is not None
        assert job.cluster_id == cluster_id_from_scan_record
        assert job.status == "pending"
        assert job.expected_scans == ["k8s", "aws", "image"]

    @pytest.mark.asyncio
    async def test_create_analysis_job_rejects_non_uuid_cluster_id(self, repo_and_session):
        repo, session = repo_and_session

        with pytest.raises(ValueError):
            await repo.create_analysis_job(
                cluster_id="not-a-uuid",
                k8s_scan_id="20260309T113020-k8s",
                aws_scan_id="20260309T113020-aws",
                image_scan_id="20260309T113020-image",
                expected_scans=["k8s", "aws", "image"],
            )

        total = await session.scalar(select(func.count()).select_from(AnalysisJob))
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_analysis_job_returns_row_by_id(self, repo_and_session):
        repo, _ = repo_and_session
        job_id = await repo.create_analysis_job(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
            expected_scans=["k8s", "image"],
        )

        job = await repo.get_analysis_job(job_id)

        assert job is not None
        assert job.id == job_id
        assert job.k8s_scan_id == "k8s-1"

    @pytest.mark.asyncio
    async def test_list_analysis_jobs_filters_by_cluster_and_status(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        other_cluster_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

        pending_job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id="img-1",
            expected_scans=["k8s", "image"],
        )
        running_job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-2",
            aws_scan_id=None,
            image_scan_id="img-2",
            expected_scans=["k8s", "image"],
        )
        await repo.create_analysis_job(
            cluster_id=other_cluster_id,
            k8s_scan_id="k8s-3",
            aws_scan_id=None,
            image_scan_id="img-3",
            expected_scans=["k8s", "image"],
        )
        running_job = await session.get(AnalysisJob, running_job_id)
        running_job.status = "running"
        await session.commit()

        cluster_jobs = await repo.list_analysis_jobs(cluster_id=cluster_id)
        running_jobs = await repo.list_analysis_jobs(cluster_id=cluster_id, status="running")

        assert {job.id for job in cluster_jobs} == {pending_job_id, running_job_id}
        assert [job.id for job in running_jobs] == [running_job_id]

    @pytest.mark.asyncio
    async def test_persist_attack_paths_creates_graph_snapshot_links_job_and_stores_edges(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            expected_scans=["k8s", "aws", "image"],
        )

        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="k8s-1-graph",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[
                {
                    "path_id": "path:0:ingress:prod:web->s3:123:data",
                    "path": ["ingress:prod:web", "pod:prod:api", "s3:123:data"],
                    "raw_final_risk": 0.91,
                    "risk_score": 0.91,
                    "length": 3,
                    "edges": [
                        {"source": "ingress:prod:web", "target": "pod:prod:api", "type": "ingress_exposes_service"},
                        {"source": "pod:prod:api", "target": "s3:123:data", "type": "iam_role_access_resource"},
                    ],
                }
            ],
        )

        uuid.UUID(graph_id)

        snapshot = await session.get(GraphSnapshot, graph_id)
        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        path = await session.scalar(select(AttackPath).where(AttackPath.graph_id == graph_id))
        edge_rows = (
            await session.execute(
                select(AttackPathEdge)
                .where(AttackPathEdge.path_id == path.id)
                .order_by(AttackPathEdge.sequence)
            )
        ).scalars().all()

        assert snapshot is not None
        assert snapshot.cluster_id == cluster_id
        assert job is not None
        assert job.graph_id == graph_id
        assert path is not None
        assert path.path_id == "path:0:ingress:prod:web->s3:123:data"
        assert path.risk_level == "critical"
        assert path.entry_node_id == "ingress:prod:web"
        assert path.target_node_id == "s3:123:data"
        assert path.node_ids == ["ingress:prod:web", "pod:prod:api", "s3:123:data"]
        assert len(edge_rows) == 2
        assert [edge.sequence for edge in edge_rows] == [0, 1]
        assert [edge.edge_type for edge in edge_rows] == [
            "ingress_exposes_service",
            "iam_role_access_resource",
        ]
        assert all(edge.path_id == path.id for edge in edge_rows)
        assert snapshot.k8s_scan_id == "k8s-1"
        assert snapshot.aws_scan_id == "aws-1"
        assert snapshot.image_scan_id == "img-1"

    @pytest.mark.asyncio
    async def test_persist_attack_paths_skips_zero_hop_self_paths(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="k8s-1-graph",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[
                {
                    "path_id": "path:0:s3:244105859679:testbed-bucket-02",
                    "path": ["s3:244105859679:testbed-bucket-02"],
                    "raw_final_risk": 0.91,
                    "risk_score": 0.91,
                    "length": 1,
                    "edges": [],
                }
            ],
        )

        path_count = await session.scalar(
            select(func.count()).select_from(AttackPath).where(AttackPath.graph_id == graph_id)
        )
        edge_count = await session.scalar(select(func.count()).select_from(AttackPathEdge))

        assert path_count == 0
        assert edge_count == 0

    @pytest.mark.asyncio
    async def test_persist_remediation_recommendations_stores_ranked_rows_for_graph(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        job_id = await repo.create_analysis_job(
            cluster_id=cluster_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            expected_scans=["k8s", "aws", "image"],
        )

        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="k8s-1-graph",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[],
        )

        await repo.persist_remediation_recommendations(
            cluster_id=cluster_id,
            graph_id=graph_id,
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            remediation_optimization={
                "summary": {"selected_count": 2},
                "recommendations": [
                    {
                        "id": "restrict_ingress:ingress:prod:web:service:prod:web:ingress_exposes_service",
                        "edge_source": "ingress:prod:web",
                        "edge_target": "service:prod:web",
                        "edge_type": "ingress_exposes_service",
                        "fix_type": "restrict_ingress",
                        "fix_description": "Restrict ingress exposure.",
                        "blocked_path_ids": ["path-a", "path-b"],
                        "blocked_path_indices": [0, 1],
                        "fix_cost": 1.0,
                        "edge_score": 1.5,
                        "covered_risk": 1.5,
                        "cumulative_risk_reduction": 1.5,
                        "metadata": {"edge_source_type": "ingress"},
                    },
                    {
                        "id": "remove_privileged:pod:prod:escape:node:worker-1:escapes_to",
                        "edge_source": "pod:prod:escape",
                        "edge_target": "node:worker-1",
                        "edge_type": "escapes_to",
                        "fix_type": "remove_privileged",
                        "fix_description": "Remove the privileged pod config.",
                        "blocked_path_ids": ["path-c"],
                        "blocked_path_indices": [2],
                        "fix_cost": 2.2,
                        "edge_score": 0.7,
                        "covered_risk": 0.7,
                        "cumulative_risk_reduction": 2.2,
                        "metadata": {"edge_source_type": "pod"},
                    },
                ],
            },
        )

        snapshot = await session.get(GraphSnapshot, graph_id)
        job = await session.scalar(select(AnalysisJob).where(AnalysisJob.id == job_id))
        rows = (
            await session.execute(
                select(RemediationRecommendation)
                .where(RemediationRecommendation.graph_id == graph_id)
                .order_by(RemediationRecommendation.recommendation_rank)
            )
        ).scalars().all()

        assert snapshot is not None
        assert snapshot.cluster_id == cluster_id
        assert job is not None
        assert job.graph_id == graph_id
        assert [row.recommendation_rank for row in rows] == [0, 1]
        assert [row.fix_type for row in rows] == ["restrict_ingress", "remove_privileged"]
        assert rows[0].blocked_path_ids == ["path-a", "path-b"]
        assert rows[0].covered_risk == 1.5
        assert rows[0].cumulative_risk_reduction == 1.5
        assert rows[1].cumulative_risk_reduction == 2.2

    @pytest.mark.asyncio
    async def test_persist_graph_inserts_rows_without_graph_edges_edge_id_assumption(self, repo_and_session):
        import networkx as nx

        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[],
        )

        graph = nx.DiGraph()
        graph.add_node(
            "ingress:prod:web",
            id="ingress:prod:web",
            type="ingress",
            is_entry_point=True,
            is_crown_jewel=False,
            base_risk=0.95,
            metadata={"namespace": "prod"},
        )
        graph.add_node(
            "s3:123456789012:prod-secrets",
            id="s3:123456789012:prod-secrets",
            type="s3_bucket",
            is_entry_point=False,
            is_crown_jewel=True,
            base_risk=0.91,
            metadata={"account_id": "123456789012"},
        )
        graph.add_edge(
            "ingress:prod:web",
            "s3:123456789012:prod-secrets",
            type="reaches",
            metadata={"protocol": "https"},
        )

        await repo.persist_graph(graph_id=graph_id, graph=graph)

        node_rows = (
            await session.execute(
                text("SELECT graph_id, node_id, node_type, is_entry_point, is_crown_jewel FROM graph_nodes WHERE graph_id = :gid ORDER BY node_id"),
                {"gid": graph_id},
            )
        ).mappings().all()
        edge_rows = (
            await session.execute(
                text(
                    "SELECT id, graph_id, source_node_id, target_node_id, edge_type "
                    "FROM graph_edges WHERE graph_id = :gid ORDER BY id"
                ),
                {"gid": graph_id},
            )
        ).mappings().all()
        assert [row["graph_id"] for row in node_rows] == [graph_id, graph_id]
        assert [row["node_id"] for row in node_rows] == ["ingress:prod:web", "s3:123456789012:prod-secrets"]
        assert bool(node_rows[0]["is_entry_point"]) is True
        assert bool(node_rows[1]["is_crown_jewel"]) is True
        assert len(edge_rows) == 1
        uuid.UUID(edge_rows[0]["id"])
        assert edge_rows[0]["graph_id"] == graph_id
        assert edge_rows[0]["source_node_id"] == "ingress:prod:web"
        assert edge_rows[0]["target_node_id"] == "s3:123456789012:prod-secrets"
        assert edge_rows[0]["edge_type"] == "reaches"

    @pytest.mark.asyncio
    async def test_persist_graph_uses_uuid_graph_edge_ids_distinct_from_attack_path_edge_row_ids(self, repo_and_session):
        import networkx as nx

        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[
                {
                    "path_id": "path:0:ingress:prod:web->s3:123456789012:prod-secrets",
                    "path": ["ingress:prod:web", "s3:123456789012:prod-secrets"],
                    "raw_final_risk": 0.91,
                    "risk_score": 0.91,
                    "length": 2,
                    "edges": [
                        {
                            "source": "ingress:prod:web",
                            "target": "s3:123456789012:prod-secrets",
                            "type": "reaches",
                        }
                    ],
                }
            ],
        )

        graph = nx.DiGraph()
        graph.add_node(
            "ingress:prod:web",
            id="ingress:prod:web",
            type="ingress",
            is_entry_point=True,
            is_crown_jewel=False,
            base_risk=0.95,
            metadata={"namespace": "prod"},
        )
        graph.add_node(
            "s3:123456789012:prod-secrets",
            id="s3:123456789012:prod-secrets",
            type="s3_bucket",
            is_entry_point=False,
            is_crown_jewel=True,
            base_risk=0.91,
            metadata={"account_id": "123456789012"},
        )
        graph.add_edge(
            "ingress:prod:web",
            "s3:123456789012:prod-secrets",
            type="reaches",
            metadata={"protocol": "https"},
        )

        await repo.persist_graph(graph_id=graph_id, graph=graph)

        persisted_edge_id = (
            await session.execute(
                text("SELECT id FROM graph_edges WHERE graph_id = :gid"),
                {"gid": graph_id},
            )
        ).scalar_one()
        path_edge_row_ids = (
            await session.execute(
                text(
                    """
                    SELECT ape.id
                    FROM attack_path_edges ape
                    JOIN attack_paths ap ON ap.id = ape.path_id
                    WHERE ap.graph_id = :gid
                    ORDER BY ape.sequence
                    """
                ),
                {"gid": graph_id},
            )
        ).scalars().all()

        uuid.UUID(persisted_edge_id)
        assert len(path_edge_row_ids) == 1
        assert path_edge_row_ids[0] != persisted_edge_id

    @pytest.mark.asyncio
    async def test_finalize_graph_snapshot_marks_completed_with_real_counts(self, repo_and_session):
        repo, session = repo_and_session
        cluster_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        graph_id = await repo.persist_attack_paths(
            cluster_id=cluster_id,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            attack_paths=[],
        )

        await repo.finalize_graph_snapshot(
            graph_id=graph_id,
            node_count=2,
            edge_count=1,
            entry_point_count=1,
            crown_jewel_count=1,
        )

        snapshot = await session.get(GraphSnapshot, graph_id)

        assert snapshot is not None
        assert snapshot.status == "completed"
        assert snapshot.node_count == 2
        assert snapshot.edge_count == 1
        assert snapshot.entry_point_count == 1
        assert snapshot.crown_jewel_count == 1
        assert snapshot.completed_at is not None

    @pytest.mark.asyncio
    async def test_persist_facts_inserts_rows_aligned_with_in_memory_fact_count(self, repo_and_session):
        repo, session = repo_and_session
        await session.execute(text("""
            CREATE TABLE facts (
                id TEXT PRIMARY KEY,
                analysis_job_id TEXT NULL,
                graph_id TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                k8s_scan_id TEXT NULL,
                aws_scan_id TEXT NULL,
                image_scan_id TEXT NULL,
                fact_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                metadata JSON NULL,
                created_at TIMESTAMP NULL
            )
        """))
        await session.commit()

        facts = [
            Fact(
                fact_type="pod_uses_service_account",
                subject_id="pod:prod:api",
                subject_type="pod",
                object_id="sa:prod:api",
                object_type="service_account",
                metadata={"source": "k8s"},
            ),
            Fact(
                fact_type="service_account_assumes_iam_role",
                subject_id="sa:prod:api",
                subject_type="service_account",
                object_id="iam:123456789012:AppRole",
                object_type="iam_role",
                metadata={"source": "aws"},
            ),
        ]
        setattr(facts[0], "_persisted_scan_id", "k8s-1")
        setattr(facts[1], "_persisted_scan_id", "aws-1")

        await repo.persist_facts(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            analysis_job_id="job-123",
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id="aws-1",
            image_scan_id="img-1",
            facts=facts,
        )

        facts_table = await repo._reflect_table("facts")
        assert facts_table is not None
        rows = (
            await session.execute(
                select(
                    facts_table.c.graph_id,
                    facts_table.c.scan_id,
                    facts_table.c.fact_type,
                    facts_table.c.subject_id,
                    facts_table.c.object_id,
                    facts_table.c.metadata,
                    facts_table.c.created_at,
                ).order_by(facts_table.c.fact_type)
            )
        ).all()

        assert len(rows) == len(facts)
        assert rows[0].graph_id == "11111111-1111-1111-1111-111111111111"
        assert rows[0].scan_id == "k8s-1"
        assert rows[0].fact_type == "pod_uses_service_account"
        assert rows[1].scan_id == "aws-1"
        assert rows[1].fact_type == "service_account_assumes_iam_role"
        assert rows[0].metadata == {"source": "k8s"}
        assert isinstance(rows[0].created_at, datetime)

    @pytest.mark.asyncio
    async def test_persist_facts_parses_iso_created_at_to_datetime(self, repo_and_session):
        repo, session = repo_and_session
        await session.execute(text("""
            CREATE TABLE facts (
                id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                fact_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                metadata JSON NULL,
                created_at TIMESTAMP NULL
            )
        """))
        await session.commit()

        fact = Fact(
            fact_type="pod_uses_service_account",
            subject_id="pod:prod:api",
            subject_type="pod",
            object_id="sa:prod:api",
            object_type="service_account",
            metadata={"source": "k8s"},
            created_at="2026-03-23T10:01:22.189526Z",
        )
        setattr(fact, "_persisted_scan_id", "k8s-1")

        await repo.persist_facts(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            analysis_job_id=None,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id=None,
            facts=[fact],
        )

        facts_table = await repo._reflect_table("facts")
        assert facts_table is not None
        row = (
            await session.execute(select(facts_table.c.scan_id, facts_table.c.created_at, facts_table.c.metadata))
        ).one()

        assert row.scan_id == "k8s-1"
        assert isinstance(row.created_at, datetime)
        assert row.created_at.replace(tzinfo=timezone.utc) == datetime(2026, 3, 23, 10, 1, 22, 189526, tzinfo=timezone.utc)
        assert row.metadata == {"source": "k8s"}

    @pytest.mark.asyncio
    async def test_persist_facts_replaces_existing_rows_for_same_graph(self, repo_and_session):
        repo, session = repo_and_session
        await session.execute(text("""
            CREATE TABLE facts (
                id TEXT PRIMARY KEY,
                graph_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                fact_type TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_type TEXT NOT NULL,
                metadata JSON NULL
            )
        """))
        await session.commit()

        await repo.persist_facts(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            analysis_job_id=None,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id=None,
            facts=[
                Fact(
                    fact_type="old_fact",
                    subject_id="a",
                    subject_type="pod",
                    object_id="b",
                    object_type="service_account",
                )
            ],
        )
        await repo.persist_facts(
            cluster_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            analysis_job_id=None,
            graph_id="11111111-1111-1111-1111-111111111111",
            k8s_scan_id="k8s-1",
            aws_scan_id=None,
            image_scan_id=None,
            facts=[
                Fact(
                    fact_type="new_fact",
                    subject_id="c",
                    subject_type="pod",
                    object_id="d",
                    object_type="service_account",
                )
            ],
        )

        rows = (await session.execute(text("SELECT fact_type FROM facts"))).all()
        assert [row.fact_type for row in rows] == ["new_fact"]
