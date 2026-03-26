from sqlalchemy import UniqueConstraint

from app.gateway.models import AnalysisJob, Cluster, LLMProviderConfig, ScanRecord, User


def test_user_model_exists_with_expected_fields():
    assert User.__tablename__ == "users"
    columns = User.__table__.columns
    assert "id" in columns
    assert "email" in columns
    assert "password_hash" in columns
    assert "is_active" in columns
    assert "created_at" in columns
    assert "updated_at" in columns


def test_user_owned_models_expose_nullable_user_id_columns():
    assert Cluster.__table__.columns["user_id"].nullable is True
    assert AnalysisJob.__table__.columns["user_id"].nullable is True
    assert ScanRecord.__table__.columns["user_id"].nullable is True
    assert LLMProviderConfig.__table__.columns["user_id"].nullable is True


def test_scan_record_cluster_id_uses_same_uuid_type_as_cluster_id():
    assert type(ScanRecord.__table__.columns["cluster_id"].type) is type(Cluster.__table__.columns["id"].type)


def test_user_relationships_are_wired_on_both_sides():
    assert "clusters" in User.__mapper__.relationships
    assert "analysis_jobs" in User.__mapper__.relationships
    assert "scan_records" in User.__mapper__.relationships
    assert "llm_provider_configs" in User.__mapper__.relationships

    assert "user" in Cluster.__mapper__.relationships
    assert "user" in AnalysisJob.__mapper__.relationships
    assert "user" in ScanRecord.__mapper__.relationships
    assert "user" in LLMProviderConfig.__mapper__.relationships


def test_llm_provider_config_no_longer_implies_global_provider_uniqueness():
    provider_column = LLMProviderConfig.__table__.columns["provider"]
    assert provider_column.unique is not True

    unique_constraints = [constraint for constraint in LLMProviderConfig.__table__.constraints if isinstance(constraint, UniqueConstraint)]
    constrained_columns = [tuple(column.name for column in constraint.columns) for constraint in unique_constraints]
    assert ("provider",) not in constrained_columns
