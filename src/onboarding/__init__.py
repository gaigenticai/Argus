"""Org-onboarding orchestration.

This package wires the once-per-org intel-collection setup tasks
(brand-search feeds, stealer-marketplace placeholders, VIP scaffolding,
typosquat schedule, NEEDS_REVIEW threshold, etc.) into a single
idempotent entry point that runs on org creation and is also safe to
re-run as a backfill.
"""
