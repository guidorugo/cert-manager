"""Tests for the dark theme toggle in the base layout."""


class TestDarkTheme:
    def test_login_page_includes_theme_bootstrap_script(self, client):
        """The head script must set data-bs-theme before first paint."""
        resp = client.get("/auth/login")
        html = resp.data.decode()
        assert resp.status_code == 200
        assert "data-bs-theme" in html
        assert "prefers-color-scheme" in html
        assert "localStorage.getItem('theme')" in html

    def test_login_page_has_floating_theme_toggle(self, client):
        """Unauthenticated pages get the floating toggle button."""
        resp = client.get("/auth/login")
        html = resp.data.decode()
        assert "theme-toggle" in html

    def test_authenticated_page_has_navbar_theme_toggle(self, auth_admin):
        """Authenticated pages get the toggle in the navbar."""
        resp = auth_admin.get("/")
        html = resp.data.decode()
        assert resp.status_code == 200
        assert "theme-toggle" in html

    def test_no_hardcoded_light_only_pre_blocks(self, auth_admin):
        """PEM blocks use adaptive bg-body-tertiary, not bg-light."""
        resp = auth_admin.get("/")
        assert b"bg-light" not in resp.data
