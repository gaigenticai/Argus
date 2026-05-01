"""Compliance Evidence Pack — exporters and mapping engine (P1 #1.3).

Public surface:
  - ``catalog`` — control catalog data + idempotent seeder
  - ``mapper`` — pure function {alert/case/finding} → list[control]
  - ``oscal``  — NIST OSCAL 1.1.2 Assessment Results emitter
  - ``pdf_exporter`` — bilingual PDF generator
"""
