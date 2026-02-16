# DeployGuard Analysis Service

## 목적

`deployguard-analysis` 서비스는 DeployGuard 보안 플랫폼의 핵심 구성 요소입니다.  
이 서비스는 보안 로그 및 인프라 데이터를 분석하여 그래프 기반 모델링을 통해 위험 요소와 잠재적 공격 경로를 식별합니다.

### 주요 기능

- **Graph Building**: OpenSearch 데이터를 기반으로 인프라 그래프를 구성합니다.
- **Path Finding**: BFS/DFS 알고리즘을 사용하여 잠재적 공격 경로를 탐색합니다.
- **Risk Scoring**: 공격 경로 및 보안 이벤트에 대한 위험 점수를 계산하고 저장합니다.
- **Alert Merging**: PostgreSQL을 사용하여 관련 보안 알림을 병합하고 상태를 관리합니다.
- **Explanation Layer**: 분석 결과를 사람이 이해할 수 있는 형태의 설명으로 제공합니다.

---

## 기술 스택

- **Python 3.11+**
- **FastAPI**: 웹 프레임워크
- **NetworkX**: 그래프 모델링 및 알고리즘 처리
- **SQLAlchemy (Async)**: PostgreSQL ORM
- **OpenSearch Python Client**: 데이터 조회 및 저장
- **Pydantic**: 데이터 검증 및 설정 관리

---

## 시작하기

### 사전 요구 사항

- Docker 및 Docker Compose
- Python 3.11 (로컬 개발용)

---

### 로컬 실행 방법

1. 레포지토리를 클론합니다.
2. 가상 환경을 생성합니다:  
   `python -m venv venv`
3. 가상 환경을 활성화합니다:  
   `source venv/bin/activate`
4. 의존성을 설치합니다:  
   `pip install -r requirements.txt`
5. `.env.example` 파일을 `.env`로 복사한 후 환경 변수를 수정합니다.
6. 애플리케이션을 실행합니다:  
   `uvicorn app.main:app --reload`

---

### Docker로 실행하기

```bash
docker build -t deployguard-analysis .
docker run -p 8000:8000 deployguard-analysis
```

---

## 환경 변수

필수 환경 변수는 다음과 같습니다 (`.env.example` 참고):

- `DATABASE_URL`: PostgreSQL 연결 문자열 (asyncpg 형식)
- `OPENSEARCH_HOST`: OpenSearch 클러스터 호스트
- `OPENSEARCH_PORT`: OpenSearch 클러스터 포트
- `OPENSEARCH_USER`: OpenSearch 사용자 이름
- `OPENSEARCH_PASSWORD`: OpenSearch 비밀번호

---

## API 문서

서비스 실행 후 다음 주소에서 API 문서를 확인할 수 있습니다:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 테스트

pytest를 사용하여 테스트를 실행할 수 있습니다:

```bash
pytest
```
