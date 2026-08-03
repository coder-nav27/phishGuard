"""Tests for the weighted risk score aggregation logic."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.base import CTIResponse
from cti.risk_scorer import compute_risk_score, WEIGHTS


def make_cti(source: str, score: float, hit: bool = False) -> CTIResponse:
    return CTIResponse(source=source, hit=hit, score=score, details={})


class TestWeights:
    def test_weights_sum_to_one(self):
        assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


class TestScoreComputation:
    def test_all_zero_gives_zero(self):
        score, level, explanation = compute_risk_score(0.0, [])
        assert score == 0.0
        assert level == "safe"

    def test_pure_ml_score(self):
        score, level, _ = compute_risk_score(1.0, [])
        assert abs(score - WEIGHTS["ml"]) < 1e-6

    def test_all_sources_max_gives_one(self):
        ctis = [
            make_cti("virustotal", 1.0, hit=True),
            make_cti("urlhaus", 1.0, hit=True),
            make_cti("whois", 1.0, hit=True),
        ]
        score, level, _ = compute_risk_score(1.0, ctis)
        assert score == 1.0
        assert level == "malicious"

    def test_score_capped_at_one(self):
        ctis = [make_cti("virustotal", 2.0, hit=True)]
        score, _, _ = compute_risk_score(2.0, ctis)
        assert score <= 1.0

    def test_score_is_rounded_to_4dp(self):
        score, _, _ = compute_risk_score(0.333, [])
        assert score == round(score, 4)


class TestThresholds:
    def test_safe_below_030(self):
        score, level, _ = compute_risk_score(0.0, [])
        assert level == "safe"

    def test_suspicious_between_030_and_065(self):
        # Need score in [0.30, 0.65) — pure ML at 0.75 → 0.75*0.40 = 0.30
        score, level, _ = compute_risk_score(0.75, [])
        assert level == "suspicious"

    def test_malicious_at_065(self):
        ctis = [make_cti("urlhaus", 1.0, hit=True)]
        # ML=1.0*0.40 + urlhaus=1.0*0.20 = 0.60 — still suspicious
        # Add VT to push past 0.65
        ctis2 = [
            make_cti("urlhaus", 1.0, hit=True),
            make_cti("virustotal", 1.0, hit=True),
        ]
        score, level, _ = compute_risk_score(1.0, ctis2)
        assert level == "malicious"
        assert score >= 0.65


class TestExplanation:
    def test_no_explanation_when_all_clear(self):
        _, _, explanation = compute_risk_score(0.0, [])
        assert explanation == []

    def test_ml_explanation_above_50pct(self):
        _, _, explanation = compute_risk_score(0.8, [])
        assert any("ML" in e for e in explanation)

    def test_vt_explanation_on_hit(self):
        ctis = [make_cti("virustotal", 0.5, hit=True)]
        _, _, explanation = compute_risk_score(0.0, ctis)
        assert any("VirusTotal" in e for e in explanation)

    def test_urlhaus_explanation_on_hit(self):
        ctis = [make_cti("urlhaus", 1.0, hit=True)]
        _, _, explanation = compute_risk_score(0.0, ctis)
        assert any("URLhaus" in e for e in explanation)

    def test_whois_explanation_on_hit(self):
        ctis = [CTIResponse(
            source="whois", hit=True, score=0.8,
            details={"domain_age_days": 3}
        )]
        _, _, explanation = compute_risk_score(0.0, ctis)
        assert any("3 days" in e for e in explanation)

    def test_missing_cti_source_defaults_to_zero(self):
        score, _, _ = compute_risk_score(0.0, [])
        assert score == 0.0
