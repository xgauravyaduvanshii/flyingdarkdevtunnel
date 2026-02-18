# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project generally follows semantic versioning principles.

## [Unreleased]

### Added
- Open-source community files and governance docs.
- Enhanced README and flow-diagram documentation.
- New `docs/how-it-works.md` deep technical flow guide.

## [0.1.0] - 2026-02-18

### Added
- Monorepo foundation (`pnpm` + Turbo) with web, API, workers, relay, and CLI.
- HTTP/HTTPS/TCP tunneling foundations with relay and agent session flow.
- Control plane APIs for auth, tunnels, requests, domains, billing, and admin.
- Billing support for Stripe/Razorpay/PayPal with webhook idempotency and replay.
- Domain and TLS lifecycle tracking with cert event ingest and policy controls.
- Admin operations for cert events/incidents, finance workflows, and audit chain checks.
- Integration tests, smoke/resilience scripts, and CI workflows.

[Unreleased]: https://github.com/xgauravyaduvanshii/flyingdarkdevtunnel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xgauravyaduvanshii/flyingdarkdevtunnel/releases/tag/v0.1.0
