"""Universal Unity Photon patcher.

Repoints Photon AppIds / AppVersions inside Unity games (Mono and IL2CPP) so a
private or self-hosted Photon deployment can be used instead of the one the
game shipped with.

Public entry points live in :mod:`photonpatcher.scan` (detection),
:mod:`photonpatcher.patch` (apply / verify / restore) and
:mod:`photonpatcher.gui` (desktop UI).
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
