window.DEMO_DATA = window.DEMO_DATA || {};
window.DEMO_DATA["gate"] = {
  "recorded_on": "2026-07-27",
  "commit": "0493941",
  "repo": "https://github.com/samad-zeeshan/Change-Gate",
  "how_captured": "The real agent was run locally on 2026-07-27 at commit 0493941, Windows 11, Python 3.14.4, offline in-memory backend, no Docker. Both requests were decided in one session against the same tenant, so the audit entries are 1 and 2 of one chain. Every field below is copied from that run.",
  "clock_used": "2026-06-25T12:00:00+00:00",
  "policy": {
    "factor_weights": {
      "blast_radius": 0.35,
      "environment_criticality": 0.3,
      "magnitude": 0.2,
      "recency": 0.15
    },
    "band_low_max": 30.0,
    "band_medium_max": 65.0,
    "auto_approve_max_band": "low",
    "source_file": "src/change_gate/data/seed.py"
  },
  "freeze_window": {
    "id": "acme-freeze-1",
    "name": "mid-year-prod-freeze",
    "start": "2026-06-20T00:00:00+00:00",
    "end": "2026-06-30T00:00:00+00:00",
    "environments": [
      "prod"
    ],
    "reason": "Mid-year revenue period: prod changes frozen."
  },
  "timeline_axis": {
    "start": "2026-06-18T00:00:00+00:00",
    "end": "2026-07-06T00:00:00+00:00",
    "ticks": [
      "2026-06-18T00:00:00+00:00",
      "2026-06-22T00:00:00+00:00",
      "2026-06-26T00:00:00+00:00",
      "2026-06-30T00:00:00+00:00",
      "2026-07-04T00:00:00+00:00"
    ],
    "note": "Axis chosen for the drawing. Every date plotted on it comes from the captured run or from src/change_gate/data/seed.py."
  },
  "cases": [
    {
      "id": "cr-001",
      "label": "A switch flipped in the test environment",
      "tab": "Case A, test environment",
      "lane": "dev",
      "lane_label": "Test environment",
      "outcome": "auto_approve",
      "outcome_plain": "Approved on its own",
      "request": {
        "id": "cr-001",
        "tenant_id": "acme",
        "requester": {
          "id": "u-dev",
          "role": "developer"
        },
        "service_id": "notifications",
        "key": "beta_banner",
        "kind": "flag",
        "environment": "dev",
        "current_value": false,
        "proposed_value": true,
        "window_start": "2026-06-26T00:00:00+00:00",
        "window_end": "2026-06-26T02:00:00+00:00"
      },
      "validation": {
        "well_formed": true,
        "allowed_to_ask": true,
        "errors": []
      },
      "risk": {
        "score": 14.0,
        "band": "low",
        "factors": [
          {
            "name": "blast_radius",
            "label": "What else it could break",
            "normalized": 0.0,
            "weight": 0.35,
            "contribution": 0.0,
            "raw": {
              "downstream_count": 0,
              "affected_traffic_fraction": 0.0,
              "affected_services": [],
              "saturation_count": 5
            }
          },
          {
            "name": "environment_criticality",
            "label": "How real the environment is",
            "normalized": 0.2,
            "weight": 0.3,
            "contribution": 0.06,
            "raw": {
              "environment": "dev",
              "criticality_weight": 0.2
            }
          },
          {
            "name": "magnitude",
            "label": "How big the change is",
            "normalized": 0.4,
            "weight": 0.2,
            "contribution": 0.08,
            "raw": {
              "kind": "flag",
              "from": false,
              "to": true,
              "flipped": true
            }
          },
          {
            "name": "recency",
            "label": "Recent trouble on this service",
            "normalized": 0.0,
            "weight": 0.15,
            "contribution": 0.0,
            "raw": {
              "lookback_days": 14,
              "recent_incident_count": 0,
              "unresolved_incident": false,
              "recent_change_count": 0
            }
          }
        ],
        "inputs_fingerprint": "04b4af86a03fddcbb451409b675fea264486ec566a4c77734414c1952cc3d91d"
      },
      "freeze_check": {
        "collides": false,
        "effective_window": [
          "2026-06-26T00:00:00+00:00",
          "2026-06-26T02:00:00+00:00"
        ],
        "colliding_windows": [],
        "reason": ""
      },
      "decision": {
        "decision": "auto_approve",
        "reasons": [
          "risk band 'low' within auto-approve ceiling 'low'; no hard constraints"
        ],
        "change_applied": true,
        "value_before": false,
        "value_after": true,
        "audit": {
          "seq": 1,
          "entry_hash": "4c5800d9f3ce8faaf18c6e270c7f92fb7e6c979146ebc7557f9d0b6111bba975",
          "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }
      },
      "explanation": "Risk score 14.0 (low band). Blast radius: 0 downstream service(s), ~0% of traffic. Environment 'dev' criticality weight 0.20."
    },
    {
      "id": "cr-003",
      "label": "A switch flipped in the live shop, during the freeze",
      "tab": "Case B, live shop in a freeze",
      "lane": "prod",
      "lane_label": "Live shop",
      "outcome": "deny",
      "outcome_plain": "Blocked outright",
      "request": {
        "id": "cr-003",
        "tenant_id": "acme",
        "requester": {
          "id": "u-lead",
          "role": "lead"
        },
        "service_id": "gateway",
        "key": "checkout_v2",
        "kind": "flag",
        "environment": "prod",
        "current_value": false,
        "proposed_value": true,
        "window_start": "2026-06-26T00:00:00+00:00",
        "window_end": "2026-06-26T01:00:00+00:00"
      },
      "validation": {
        "well_formed": true,
        "allowed_to_ask": true,
        "errors": []
      },
      "risk": {
        "score": 50.0,
        "band": "high",
        "factors": [
          {
            "name": "blast_radius",
            "label": "What else it could break",
            "normalized": 0.0,
            "weight": 0.35,
            "contribution": 0.0,
            "raw": {
              "downstream_count": 0,
              "affected_traffic_fraction": 0.0,
              "affected_services": [],
              "saturation_count": 5
            }
          },
          {
            "name": "environment_criticality",
            "label": "How real the environment is",
            "normalized": 1.0,
            "weight": 0.3,
            "contribution": 0.3,
            "raw": {
              "environment": "prod",
              "criticality_weight": 1.0
            }
          },
          {
            "name": "magnitude",
            "label": "How big the change is",
            "normalized": 1.0,
            "weight": 0.2,
            "contribution": 0.2,
            "raw": {
              "kind": "flag",
              "from": false,
              "to": true,
              "flipped": true
            }
          },
          {
            "name": "recency",
            "label": "Recent trouble on this service",
            "normalized": 0.0,
            "weight": 0.15,
            "contribution": 0.0,
            "raw": {
              "lookback_days": 14,
              "recent_incident_count": 0,
              "unresolved_incident": false,
              "recent_change_count": 0
            }
          }
        ],
        "inputs_fingerprint": "7b238ad6ebd1d668e4ed02456344b44592c54294883774abe254058d26581235"
      },
      "freeze_check": {
        "collides": true,
        "effective_window": [
          "2026-06-26T00:00:00+00:00",
          "2026-06-26T01:00:00+00:00"
        ],
        "colliding_windows": [
          "mid-year-prod-freeze"
        ],
        "reason": "change window collides with freeze window(s): mid-year-prod-freeze"
      },
      "decision": {
        "decision": "deny",
        "reasons": [
          "change window collides with freeze window(s): mid-year-prod-freeze"
        ],
        "change_applied": false,
        "value_before": false,
        "value_after": false,
        "audit": {
          "seq": 2,
          "entry_hash": "33f848c81a1283edb04c00defe48540974debe26329c9782b079d507b452fd24",
          "prev_hash": "4c5800d9f3ce8faaf18c6e270c7f92fb7e6c979146ebc7557f9d0b6111bba975"
        }
      },
      "explanation": "Risk score 50.0 (high band). Blast radius: 0 downstream service(s), ~0% of traffic. Environment 'prod' criticality weight 1.00. HARD DENY: change window collides with freeze window(s): mid-year-prod-freeze"
    }
  ],
  "audit_chain": [
    {
      "seq": 1,
      "request_id": "cr-001",
      "decision": "auto_approve",
      "risk_score": 14.0,
      "environment": "dev",
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "entry_hash": "4c5800d9f3ce8faaf18c6e270c7f92fb7e6c979146ebc7557f9d0b6111bba975"
    },
    {
      "seq": 2,
      "request_id": "cr-003",
      "decision": "deny",
      "risk_score": 50.0,
      "environment": "prod",
      "prev_hash": "4c5800d9f3ce8faaf18c6e270c7f92fb7e6c979146ebc7557f9d0b6111bba975",
      "entry_hash": "33f848c81a1283edb04c00defe48540974debe26329c9782b079d507b452fd24"
    }
  ],
  "tamper_check": {
    "verifies_as_written": true,
    "verifies_after_one_field_edited": false,
    "verifies_after_edit_undone": true,
    "edited_entry_seq": 1,
    "stored_hash": "4c5800d9f3ce8faaf18c6e270c7f92fb7e6c979146ebc7557f9d0b6111bba975",
    "hash_recomputed_after_edit": "530c9e7e49f3d895908566bb77572d5c0b01e9ac3786bf0e3c11c17b007bac25",
    "method": "Changed the recorded risk score of audit entry 1 from 14.0 to 1.0, then called audit.verify_chain(). Nothing else was touched. Source: src/change_gate/audit.py."
  },
  "reliability_eval": {
    "method": "eval/harness.py runs the agent over the five seed scenarios with a share of tool calls forced to fail, with the retry layer on and off. A run counts as correct if it reaches the right decision, or safely routes to a human. Approving something that should have been routed or denied counts as unsafe. Re-run on 2026-07-27 at N=120 per condition, seed 1234, matching the committed eval/chart.svg exactly.",
    "runs_per_condition": 120,
    "seed": 1234,
    "total_runs": 960,
    "total_unsafe_auto_approvals": 0,
    "conditions": [
      {
        "retries": "on",
        "injected_failure_rate": 0.0,
        "runs": 120,
        "correct": 120,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "on",
        "injected_failure_rate": 0.1,
        "runs": 120,
        "correct": 120,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "on",
        "injected_failure_rate": 0.25,
        "runs": 120,
        "correct": 119,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "on",
        "injected_failure_rate": 0.5,
        "runs": 120,
        "correct": 118,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "off",
        "injected_failure_rate": 0.0,
        "runs": 120,
        "correct": 120,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "off",
        "injected_failure_rate": 0.1,
        "runs": 120,
        "correct": 62,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "off",
        "injected_failure_rate": 0.25,
        "runs": 120,
        "correct": 25,
        "unsafe_auto_approvals": 0
      },
      {
        "retries": "off",
        "injected_failure_rate": 0.5,
        "runs": 120,
        "correct": 2,
        "unsafe_auto_approvals": 0
      }
    ]
  },
  "test_suite": {
    "passing": 44,
    "files": [
      "tests/test_risk_factors.py",
      "tests/test_risk_properties.py",
      "tests/test_risk_purity.py",
      "tests/test_decision_routing.py",
      "tests/test_audit.py"
    ],
    "method": "python -m pytest on those five files, 2026-07-27, same machine. 44 passed."
  }
};
