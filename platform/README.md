# platform/

**소유: B(플랫폼) — `feature-mj` 브랜치**

검증 서비스(flag 판정·로깅), 웹 UI + 대시보드.

엔진과의 접점: 엔진이 만든 번들(`app/` + `manifest.json`)을 받아 배포한다. `manifest.json`의 `_internal` 블록(flag, 레퍼런스 익스플로잇, 정답 요약)은 절대 학생에게 노출하지 않을 것 — 자세한 인터페이스는 [`docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md`](../docs/superpowers/plans/2026-07-24-ulsaner-engine-implementation-plan.md)의 "Platform (Part B) scope" 절 참고.
