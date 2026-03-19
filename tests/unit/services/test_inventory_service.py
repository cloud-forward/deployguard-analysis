from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.application.services.inventory_service as inventory_service_module
from app.application.services.inventory_service import InventoryService, build_inventory_list_response
from app.models.schemas import ClusterCreateRequest, ClusterResponse


def make_service():
    cluster_repo = MagicMock()
    cluster_repo.create = AsyncMock()
    cluster_repo.get_by_id = AsyncMock()
    cluster_repo.list_all = AsyncMock()

    snapshot_repo = MagicMock()
    snapshot_repo.create = AsyncMock()
    snapshot_repo.get_latest_by_cluster = AsyncMock()
    snapshot_repo.list_latest = AsyncMock()

    service = InventoryService(
        cluster_repository=cluster_repo,
        inventory_snapshot_repository=snapshot_repo,
    )
    return service, cluster_repo, snapshot_repo


class TestInventoryService:
    @pytest.mark.asyncio
    async def test_create_cluster_persists_aws_fields(self):
        service, cluster_repo, _ = make_service()
        cluster_repo.create.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
            description=None,
        )

        request = ClusterCreateRequest(
            name="prod",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )

        result = await service.create_cluster(request)

        assert result.id == "c1"
        cluster_repo.create.assert_awaited_once_with(
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        assert result.aws_role_arn == "arn:aws:iam::123456789012:role/discovery"

    @pytest.mark.asyncio
    async def test_create_cluster_preserves_response_shape(self):
        service, cluster_repo, _ = make_service()
        cluster_repo.create.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
            description="aws discovery cluster",
        )

        result = await service.create_cluster(
            ClusterCreateRequest(
                name="prod",
                aws_account_id="123456789012",
                aws_role_arn="arn:aws:iam::123456789012:role/discovery",
                aws_region="ap-northeast-2",
            )
        )

        assert result.model_dump(exclude_none=True) == {
            "id": "c1",
            "name": "prod",
            "description": "aws discovery cluster",
            "cluster_type": "aws",
            "aws_account_id": "123456789012",
            "aws_role_arn": "arn:aws:iam::123456789012:role/discovery",
            "aws_region": "ap-northeast-2",
        }

    @pytest.mark.asyncio
    async def test_sync_cluster_persists_snapshot(self, monkeypatch):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )

        monkeypatch.setattr(inventory_service_module, "assume_role", lambda role_arn: f"session-for:{role_arn}")
        monkeypatch.setattr(
            inventory_service_module,
            "collect_all_assets",
            lambda session, account_id, region: {
                "scan_id": "scan-123",
                "aws_account_id": account_id,
                "region": region,
                "scanned_at": "2026-03-19T12:00:00+00:00",
                "iam_roles": [{"name": "role-a"}],
                "iam_users": [],
                "s3_buckets": [],
                "rds_instances": [],
                "ec2_instances": [],
            },
        )

        result = await service.sync_cluster("c1")

        assert result.scan_id == "scan-123"
        assert result.cluster_id == "c1"
        assert result.status == "success"
        snapshot_repo.create.assert_awaited_once()
        kwargs = snapshot_repo.create.await_args.kwargs
        assert kwargs["cluster_id"] == "c1"
        assert kwargs["scan_id"] == "scan-123"
        assert kwargs["raw_result_json"]["iam_roles"][0]["name"] == "role-a"
        assert kwargs["scanned_at"].isoformat() == "2026-03-19T12:00:00+00:00"

    @pytest.mark.asyncio
    async def test_sync_cluster_raises_404_when_cluster_missing(self):
        from fastapi import HTTPException

        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await service.sync_cluster("missing")

        assert exc_info.value.status_code == 404
        snapshot_repo.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_cluster_raises_400_when_cluster_missing_aws_config(self):
        from fastapi import HTTPException

        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="",
            aws_region="ap-northeast-2",
        )

        with pytest.raises(HTTPException) as exc_info:
            await service.sync_cluster("c1")

        assert exc_info.value.status_code == 400
        assert "missing AWS discovery configuration" in exc_info.value.detail
        snapshot_repo.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_cluster_propagates_assume_role_failure(self, monkeypatch):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        monkeypatch.setattr(
            inventory_service_module,
            "assume_role",
            lambda role_arn: (_ for _ in ()).throw(RuntimeError("sts failed")),
        )

        with pytest.raises(RuntimeError, match="sts failed"):
            await service.sync_cluster("c1")

        snapshot_repo.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_cluster_propagates_collector_failure(self, monkeypatch):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        monkeypatch.setattr(inventory_service_module, "assume_role", lambda role_arn: "session")
        monkeypatch.setattr(
            inventory_service_module,
            "collect_all_assets",
            lambda session, account_id, region: (_ for _ in ()).throw(RuntimeError("collector failed")),
        )

        with pytest.raises(RuntimeError, match="collector failed"):
            await service.sync_cluster("c1")

        snapshot_repo.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_cluster_raises_value_error_for_malformed_scanned_at(self, monkeypatch):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        monkeypatch.setattr(inventory_service_module, "assume_role", lambda role_arn: "session")
        monkeypatch.setattr(
            inventory_service_module,
            "collect_all_assets",
            lambda session, account_id, region: {
                "scan_id": "scan-123",
                "aws_account_id": account_id,
                "region": region,
                "scanned_at": "not-a-timestamp",
                "iam_roles": [],
                "iam_users": [],
                "s3_buckets": [],
                "rds_instances": [],
                "ec2_instances": [],
            },
        )

        with pytest.raises(ValueError):
            await service.sync_cluster("c1")

        snapshot_repo.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_get_cluster_assets_reads_latest_snapshot(self):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        snapshot_repo.get_latest_by_cluster.return_value = SimpleNamespace(
            cluster_id="c1",
            raw_result_json={
                "iam_roles": [],
                "iam_users": [],
                "s3_buckets": [{"name": "bucket-a", "arn": "arn:aws:s3:::bucket-a"}],
                "rds_instances": [],
                "ec2_instances": [],
            },
        )

        result = await service.get_cluster_assets("c1")

        assert result.summary.total_assets == 1
        assert result.assets[0].asset_id == "s3:bucket-a"
        assert result.assets[0].details["arn"] == "arn:aws:s3:::bucket-a"

    @pytest.mark.asyncio
    async def test_get_cluster_assets_returns_empty_when_no_snapshot_exists(self):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        snapshot_repo.get_latest_by_cluster.return_value = None

        result = await service.get_cluster_assets("c1")

        assert result.summary.total_assets == 0
        assert result.assets == []

    @pytest.mark.asyncio
    async def test_get_cluster_assets_uses_latest_snapshot(self):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        snapshot_repo.get_latest_by_cluster.return_value = SimpleNamespace(
            cluster_id="c1",
            raw_result_json={
                "iam_roles": [{"name": "role-new"}],
                "iam_users": [],
                "s3_buckets": [],
                "rds_instances": [],
                "ec2_instances": [],
            },
        )

        result = await service.get_cluster_assets("c1")

        assert [asset.asset_id for asset in result.assets] == ["iam-role:role-new"]

    @pytest.mark.asyncio
    async def test_get_asset_detail_reads_latest_snapshots(self):
        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        snapshot_repo.list_latest.return_value = [
            SimpleNamespace(
                cluster_id="c1",
                raw_result_json={
                    "iam_roles": [{"name": "role-a"}],
                    "iam_users": [],
                    "s3_buckets": [],
                    "rds_instances": [],
                    "ec2_instances": [],
                },
            )
        ]

        result = await service.get_asset_detail("iam-role:role-a")

        assert result.asset_type == "iam_role"
        assert result.name == "role-a"
        assert result.cluster_id == "c1"

    @pytest.mark.asyncio
    async def test_get_asset_detail_uses_latest_snapshot_per_cluster(self):
        service, cluster_repo, snapshot_repo = make_service()

        async def get_cluster(cluster_id: str):
            return SimpleNamespace(
                id=cluster_id,
                name=f"cluster-{cluster_id}",
                cluster_type="aws",
                aws_account_id=f"acct-{cluster_id}",
                aws_role_arn=f"arn:aws:iam::{cluster_id}:role/discovery",
                aws_region="ap-northeast-2",
            )

        cluster_repo.get_by_id.side_effect = get_cluster
        snapshot_repo.list_latest.return_value = [
            SimpleNamespace(
                cluster_id="c1",
                raw_result_json={
                    "iam_roles": [],
                    "iam_users": [],
                    "s3_buckets": [{"name": "bucket-new", "arn": "arn:aws:s3:::bucket-new"}],
                    "rds_instances": [],
                    "ec2_instances": [],
                },
            ),
            SimpleNamespace(
                cluster_id="c2",
                raw_result_json={
                    "iam_roles": [],
                    "iam_users": [],
                    "s3_buckets": [{"name": "bucket-target", "arn": "arn:aws:s3:::bucket-target"}],
                    "rds_instances": [],
                    "ec2_instances": [],
                },
            ),
        ]

        result = await service.get_asset_detail("s3:bucket-target")

        assert result.asset_id == "s3:bucket-target"
        assert result.cluster_id == "c2"
        assert result.account_id == "acct-c2"

    @pytest.mark.asyncio
    async def test_get_asset_detail_raises_404_when_not_found(self):
        from fastapi import HTTPException

        service, cluster_repo, snapshot_repo = make_service()
        cluster_repo.get_by_id.return_value = SimpleNamespace(
            id="c1",
            name="prod",
            cluster_type="aws",
            aws_account_id="123456789012",
            aws_role_arn="arn:aws:iam::123456789012:role/discovery",
            aws_region="ap-northeast-2",
        )
        snapshot_repo.list_latest.return_value = [
            SimpleNamespace(
                cluster_id="c1",
                raw_result_json={
                    "iam_roles": [{"name": "role-a"}],
                    "iam_users": [],
                    "s3_buckets": [],
                    "rds_instances": [],
                    "ec2_instances": [],
                },
            )
        ]

        with pytest.raises(HTTPException) as exc_info:
            await service.get_asset_detail("missing-asset")

        assert exc_info.value.status_code == 404

    def test_build_inventory_list_response_handles_empty_payload(self):
        cluster = ClusterResponse(id="c1", name="prod", aws_account_id="123456789012", aws_region="ap-northeast-2")

        result = build_inventory_list_response(cluster, {})

        assert result.summary.total_assets == 0
        assert result.assets == []

    def test_build_inventory_list_response_counts_assets(self):
        cluster = ClusterResponse(
            id="c1",
            name="prod",
            aws_account_id="123456789012",
            aws_region="ap-northeast-2",
        )
        scan = {
            "iam_roles": [{"name": "role-a"}],
            "iam_users": [{"username": "user-a"}],
            "s3_buckets": [{"name": "bucket-a"}],
            "rds_instances": [{"identifier": "db-a"}],
            "ec2_instances": [{"instance_id": "i-123"}],
        }

        result = build_inventory_list_response(cluster, scan)

        assert result.summary.total_assets == 5
        assert {item.asset_type for item in result.assets} == {
            "iam_role",
            "iam_user",
            "s3",
            "rds",
            "ec2",
        }

    def test_build_inventory_list_response_maps_optional_fields_without_crashing(self):
        cluster = ClusterResponse(
            id="c1",
            name="prod",
            aws_account_id="123456789012",
            aws_region="ap-northeast-2",
        )
        scan = {
            "iam_roles": [],
            "iam_users": [{"username": "user-a", "has_mfa": None}],
            "s3_buckets": [{"name": "bucket-a"}],
            "rds_instances": [{"identifier": "db-a"}],
            "ec2_instances": [{"instance_id": "i-123"}],
        }

        result = build_inventory_list_response(cluster, scan)

        assert result.summary.total_assets == 4
        s3_asset = next(asset for asset in result.assets if asset.asset_id == "s3:bucket-a")
        user_asset = next(asset for asset in result.assets if asset.asset_id == "iam-user:user-a")
        assert s3_asset.details["arn"] is None
        assert user_asset.details["has_mfa"] is None
