from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable

MODIFIED_Z_FACTOR = 0.6745


@dataclass(frozen=True)
class RobustBaseline:
    median_value: float
    mad_value: float
    sample_count: int


def median_absolute_deviation(values: Iterable[float]) -> RobustBaseline:
    prepared = [float(value) for value in values]
    if not prepared:
        raise ValueError("Cannot calculate a baseline from an empty sample.")

    center = float(median(prepared))
    deviations = [abs(value - center) for value in prepared]
    mad = float(median(deviations))
    return RobustBaseline(center, mad, len(prepared))


def modified_z_score(
    observed: float,
    baseline_median: float,
    baseline_mad: float,
    fallback_scale: float,
) -> tuple[float, float]:
    """Return a one-sided modified z-score and the scale that was used.

    A MAD of zero is common for count data. In that case a documented fallback
    scale is used so that a genuine increase can still be scored instead of
    causing division by zero.
    """
    if observed <= baseline_median:
        return 0.0, baseline_mad if baseline_mad > 0 else fallback_scale

    scale = baseline_mad if baseline_mad > 0 else fallback_scale
    if scale <= 0:
        scale = 1.0

    score = MODIFIED_Z_FACTOR * (observed - baseline_median) / scale
    return float(score), float(scale)
