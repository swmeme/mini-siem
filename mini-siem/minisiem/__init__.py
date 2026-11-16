"""Mini-SIEM: a small, dependency-free security log analysis pipeline.

The package is organized as a linear pipeline:

    sources -> parsers -> normalized events -> detection engine -> alerts
                                                        |
                                                   storage + report

See README.md and docs/ARCHITECTURE.md for the full description.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
