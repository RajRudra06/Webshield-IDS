
import numpy as _np
import lightgbm as _lgb
from lightgbm import LGBMClassifier as LGBMClassifier

# common names pickles sometimes reference
dtype = _np.dtype
np = _np
numpy = _np

__all__ = ["LGBMClassifier", "dtype", "np", "numpy"]

# fallback attribute resolver used when pickle requests other names
def __getattr__(name):
    # prefer lightgbm attributes, then numpy
    if hasattr(_lgb, name):
        return getattr(_lgb, name)
    if hasattr(_np, name):
        return getattr(_np, name)
    raise AttributeError(f"module 'LGBMClassifier' has no attribute '{name}'")
