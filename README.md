# RVO Wellness

Private-by-design personal wellness and life-coaching application.

## Architecture

Fitbit Air -> Google Health API -> RVO Wellness backend -> normalized wellness data -> trend engine -> Seven Circles coaching context.

This repository is intentionally independent from Cynergists. Personal health information, OAuth credentials, tokens, and wellness records must never be stored in or synchronized to the Cynergists CRM.

## Phase 1
- Standalone application foundation
- Google Health OAuth
- Encrypted token storage
- Per-user RLS
- Connection/audit history

## Phase 2
- Fitbit Air / Google Health ingestion
- 1-90 day synchronization
- Daily normalized metrics
- Lossless raw payload capture
- Sync observability and retries

## Security
Google Health tokens are server-only and encrypted at rest. Browser clients never receive stored refresh tokens. Health tables use row-level security.
