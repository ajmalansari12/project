/* Synthetic test rule fixture for Sentinel-EDR automated testing */

rule SyntheticThreatAlpha : test_indicator signature {
    meta:
        description = "Synthetic test indicator for Sentinel-EDR YARA scanner"
        author = "Sentinel-EDR Test Team"
        severity = "HIGH"
        synthetic_id = "SYN-001"
    strings:
        $token = "SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_ALPHA"
    condition:
        $token
}

rule SyntheticThreatBeta : test_indicator {
    meta:
        description = "Second synthetic rule for multi-match testing"
        author = "Sentinel-EDR Test Team"
        severity = "MEDIUM"
        synthetic_id = "SYN-002"
    strings:
        $token = "SENTINEL_EDR_SYNTHETIC_THREAT_PATTERN_BETA"
    condition:
        $token
}
