"""Version string for securebank_lab."""

__version__ = "2.2.1"


class QuietBannerHandler:
    """Minimal handler to test that server banners hide version info."""

    def version_string(self) -> str:
        return "SecureBank"
