import numpy as np
from typing import Dict, Any
from flows.flow_key import Flow

def extract_temporal_features(flow: Flow) -> Dict[str, Any]:
    """Extract timing, inter-arrival time (IAT), burstiness, and periodicity metrics."""
    iats = np.array(flow.all_iats) if flow.all_iats else np.array([0.0])

    if len(iats) == 0 or (len(iats) == 1 and iats[0] == 0.0):
        return {
            "mean_iat": 0.0,
            "median_iat": 0.0,
            "std_iat": 0.0,
            "cov_iat": 0.0,
            "periodicity_score": 0.0,
            "burstiness": 0.0
        }

    mean_iat = float(np.mean(iats))
    median_iat = float(np.median(iats))
    std_iat = float(np.std(iats))

    cov_iat = std_iat / (mean_iat + 1e-6)
    
    # Periodicity score: 1.0 indicates perfectly regular intervals (std -> 0)
    periodicity_score = 1.0 / (1.0 + cov_iat)

    # Burstiness index: (std - mean) / (std + mean)
    burstiness = (std_iat - mean_iat) / (std_iat + mean_iat + 1e-6)

    return {
        "mean_iat": mean_iat,
        "median_iat": median_iat,
        "std_iat": std_iat,
        "cov_iat": cov_iat,
        "periodicity_score": periodicity_score,
        "burstiness": burstiness
    }
