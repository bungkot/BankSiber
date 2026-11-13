"""Single source of truth for the package version.

``pyproject.toml`` reads this value dynamically
(``[tool.setuptools.dynamic]``), so this is the only place a release bump
touches. The banner-hiding request handler lives in
:mod:`securebank_lab.webapp.server`.
"""

__version__ = "2.2.2"
