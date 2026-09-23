"""SARIF 2.1.0, for GitHub code scanning. A wrapper over ``core.to_sarif``.

``core.to_sarif`` stays where it is because ``veridor run --sarif`` and a long
list of tests call it; this module is what makes it one format among five, with
the same input contract as the rest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from veridor import core


def render(document: Mapping[str, Any], *, root: Path | None = None) -> str:
    """The exact bytes ``veridor run --sarif`` writes for the same run.

    ``root`` is accepted for a uniform signature and deliberately unused: the
    SARIF location is the config path as the run recorded it, and changing it
    here would move every GitHub alert's tracked location.
    """
    del root
    return json.dumps(core.to_sarif(dict(document)), indent=2) + "\n"
