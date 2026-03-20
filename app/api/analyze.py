# ✨ 새로운 엔드포인트 추가
@router.get("/analysis/{job_id}/result")
async def get_analysis_result(
    job_id: str,
    service: AnalysisService = Depends(lambda: get_di_container().analysis_service()),
):
    """
    Get analysis result by job ID.
    
    Returns attack paths and risk scores.
    """
    # TODO: Implement job result retrieval from database
    return {
        "job_id": job_id,
        "status": "completed",
        "message": "Analysis result retrieval not yet implemented",
    }


@router.post("/analysis/execute")
async def execute_analysis_endpoint(
    cluster_id: str,
    k8s_scan_id: str,
    aws_scan_id: str,
    image_scan_id: str,
    service: AnalysisService = Depends(lambda: get_di_container().analysis_service()),
):
    """
    Execute analysis directly (for testing).
    
    This endpoint bypasses the job queue and executes analysis immediately.
    """
    try:
        result = await service.execute_analysis(
            cluster_id=cluster_id,
            k8s_scan_id=k8s_scan_id,
            aws_scan_id=aws_scan_id,
            image_scan_id=image_scan_id,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis execution failed: {str(e)}"
        )