"""HUNTX Intelligence Engine — correlation, mapping, endpoint passports, and diffing."""
from huntx.intelligence.endpoint_passport import (
    EndpointPassport,
    detect_auth_evidence,
    generate_endpoint_passports,
    infer_feature_group,
)
from huntx.intelligence.android_api_mapper import (
    AndroidApiMapper,
    MappingResult,
    map_android_to_apis,
)
from huntx.intelligence.apk_diff import (
    APKDiff,
    APKDiffResult,
    compare_apk_runs,
)

__all__ = [
    "EndpointPassport",
    "generate_endpoint_passports",
    "infer_feature_group",
    "detect_auth_evidence",
    "AndroidApiMapper",
    "MappingResult",
    "map_android_to_apis",
    "APKDiff",
    "APKDiffResult",
    "compare_apk_runs",
]
