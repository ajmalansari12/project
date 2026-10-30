/* Synthetic benign marker rule fixture for Sentinel-EDR automated testing */

rule HarmlessMarker : harmless {
    meta:
        description = "Harmless benign marker rule"
        author = "Sentinel-EDR Test Team"
        severity = "INFO"
    strings:
        $marker = "SENTINEL_EDR_HARMLESS_BENIGN_MARKER"
    condition:
        $marker
}
