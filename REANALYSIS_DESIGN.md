# DeployGuard Analysis Service 설계 문서

## 1. 서비스 개요

### 목적
`deployguard-analysis`는 DeployGuard 보안 플랫폼의 핵심 분석 서비스이다.  
OpenSearch에 저장된 보안 이벤트 및 인프라 데이터를 기반으로 그래프를 구성하고, 공격 경로를 탐지하며, 위험도를 계산하고, 관련 알림을 병합 및 재분석한다.

### 주요 기능

- **Graph Building**: 인프라 및 이벤트 데이터를 기반으로 그래프 생성
- **Path Finding**: BFS/DFS 기반 공격 경로 탐색
- **Risk Scoring**: 공격 경로 및 노드 기반 위험도 계산
- **Alert Merging**: PostgreSQL을 이용한 알림 그룹 병합 상태 관리
- **Reanalysis Scheduling**: 디바운스 + 슬라이딩 윈도우 기반 재분석 제어
- **Explanation Layer**: 분석 결과를 사람이 이해할 수 있는 형태로 설명 생성

---

## 2. 기술 스택

- Python 3.11+
- FastAPI
- NetworkX
- SQLAlchemy (Async)
- PostgreSQL 13+
- OpenSearch Python Client
- Pydantic

---

## 3. 시스템 구조 요약

- 알림 병합 상태는 PostgreSQL `alert_groups` 테이블에서 관리
- 슬라이딩 10분 윈도우 기반 병합 유지
- 30초 디바운스 기반 재분석 실행
- OPEN / CLOSED 두 상태만 사용
- 동시성 제어는 PostgreSQL row-level locking 사용
- 외부 Redis/Kafka 없이 DB 기반 스케줄링

---

# Reanalysis Scheduling Logic Design

## 4. 재분석 스케줄링 핵심 개념

### 설계 목표

- 10분 슬라이딩 병합 윈도우 유지 (`window_expires_at`)
- 마지막 merge 이후 30초 디바운스
- 그룹 종료 전 최종 분석 1회 보장
- 중복 실행 방지
- 고동시성 환경에서 안전성 보장

---

## 5. 이벤트 타임라인 예시

### 30초 내 다중 병합

```
T+0s     : Alert A → merge
           last_updated_at = T+0
           window_expires_at = T+10m
           next_reanalysis_at = T+30s

T+10s    : Alert B → merge
           window_expires_at = T+10m+10s
           next_reanalysis_at = T+40s (reset)

T+25s    : Alert C → merge
           window_expires_at = T+10m+25s
           next_reanalysis_at = T+55s (reset)

T+55s    : 디바운스 만료 → 분석 실행 (OPEN 유지)

T+10m25s : 윈도우 만료 → 최종 분석 → CLOSED 전환
```

### 핵심 원칙

- merge 발생 시:
  - last_updated_at 갱신
  - window_expires_at 자동 슬라이딩
  - next_reanalysis_at = now() + 30초
- OPEN 상태에서 여러 번 분석 가능
- 종료 시점에 반드시 최종 분석 수행

---

## 6. Debounce 구현 방식

### DB 기반 스케줄링 (권장)

`alert_groups`에 다음 컬럼 사용:

- `next_reanalysis_at TIMESTAMPTZ`
- `last_analysis_at TIMESTAMPTZ`

### Worker Poll 쿼리

```sql
SELECT id
FROM alert_groups
WHERE is_open = TRUE
  AND next_reanalysis_at IS NOT NULL
  AND next_reanalysis_at <= now()
ORDER BY next_reanalysis_at ASC
FOR UPDATE SKIP LOCKED
LIMIT 10;
```

### 분석 완료 후

```sql
UPDATE alert_groups
SET next_reanalysis_at = NULL,
    last_analysis_at = now()
WHERE id = :id;
```

---

## 7. 윈도우 만료 시 최종 분석

### 트리거 조건

```sql
WHERE is_open = TRUE
  AND window_expires_at <= now()
```

### 실행 로직

1. FOR UPDATE SKIP LOCKED 로 row claim
2. 최종 분석 수행
3. 다음 UPDATE를 단일 트랜잭션에서 수행:

```sql
UPDATE alert_groups
SET is_open = FALSE,
    closed_at = now(),
    next_reanalysis_at = NULL,
    last_analysis_at = now()
WHERE id = :id
  AND window_expires_at <= now();
```

### 레이스 컨디션 보호

- merge가 먼저 들어오면 window_expires_at이 슬라이딩됨
- 위 UPDATE 조건이 실패하여 종료되지 않음
- 그룹은 OPEN 유지

---

## 8. 중복 실행 방지 전략

PostgreSQL의 `FOR UPDATE SKIP LOCKED` 사용:

- 동일 row를 두 worker가 동시에 처리 불가
- 트랜잭션 종료 시 lock 자동 해제
- worker crash 시 자동 rollback → lock 해제

별도 boolean mutex 컬럼은 사용하지 않음.

---

## 9. 장애 대응 전략

### Worker Crash
- 트랜잭션 자동 롤백
- lock 해제
- 다음 worker가 재처리

### 분석 실패
- next_reanalysis_at에 backoff 시간 설정
- 반복 실패 시 meta JSON에 상태 기록

### Deadlock
- id ASC 정렬 유지
- exponential backoff 재시도

### Zombie Task 정리
```sql
UPDATE alert_groups
SET next_reanalysis_at = now()
WHERE is_open = TRUE
  AND next_reanalysis_at < now() - INTERVAL '1 hour';
```

---

## 10. 성능 고려사항

- Partial index: next_reanalysis_at WHERE is_open = TRUE
- Partial index: window_expires_at WHERE is_open = TRUE
- Worker poll 주기: 1초
- 윈도우 만료 체크 주기: 10초

---

## 11. 설계 요약

이 설계는 다음을 보장한다:

- 슬라이딩 윈도우 기반 병합 정확성
- 30초 디바운스 기반 재분석 안정성
- 최종 분석 1회 보장
- 중복 실행 방지
- ACID 기반 동시성 안전성
- 외부 메시지 큐 없이 수평 확장 가능

PostgreSQL의 row-level locking을 단일 진실 소스로 사용하여, 최소한의 상태와 구조로 production-grade 재분석 스케줄링을 구현한다.
