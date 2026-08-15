"""Which secret gets asked for, and what happens when the answer is no.

The property that matters most here is negative: **a name that is not in the
inventory is never requested.** Every such request is a notification on
somebody's phone for a secret that does not exist, which is what the old
``./aw ssh`` did on every typo.
"""
from __future__ import annotations

import pytest

from ssh_app import credentials as creds
from ssh_app.credentials import ApprovalRefused, Credential, CredentialError
from ssh_app.target import Target

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"


class _Api:
    """Scripted stand-in for the workspace HTTP API."""

    def __init__(self, names=(), read=None):
        self.names = list(names)
        self.read = read or (200, {"status": "approved", "value": KEY})
        self.calls = []

    def __call__(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if method == "GET" and "/requests/" in path:
            return self.read          # polling an outstanding approval
        if method == "GET":
            return 200, {"secrets": [{"name": n} for n in self.names]}
        return self.read


@pytest.fixture
def api(monkeypatch):
    def _install(names=(), read=None):
        fake = _Api(names, read)
        monkeypatch.setattr(creds, "request", fake)
        return fake
    return _install


# ── name resolution ──────────────────────────────────────────────────────

def test_the_legacy_name_is_tried_first():
    """The live vault is full of ``private_<user>_<host>`` from ./aw ssh. A
    resolver that preferred a newer convention would find nothing for hosts
    that have worked for a year."""
    assert creds.candidate_names(Target("root", "h"))[0] == "private_root_h"


def test_resolves_the_exact_name(api):
    api(["private_root_h", "ssh_h"])
    assert creds.resolve_name(Target("root", "h")) == "private_root_h"


def test_a_host_wide_entry_covers_a_named_user(api):
    api(["ssh_h"])
    assert creds.resolve_name(Target("root", "h")) == "ssh_h"


def test_no_user_falls_back_to_the_single_match_for_that_host(api):
    """``aw-workspace-cli ssh box`` has no user to build a name from. One
    candidate is unambiguous, so use it."""
    api(["private_deploy_box", "resend_api_key"])
    assert creds.resolve_name(Target(None, "box")) == "private_deploy_box"


def test_two_matches_for_one_host_is_an_error_not_a_choice(api):
    """Picking either would connect as a user the caller never named."""
    api(["private_root_box", "private_deploy_box"])
    with pytest.raises(CredentialError, match="did not say which user"):
        creds.resolve_name(Target(None, "box"))


def test_nothing_matching_never_reaches_the_read_endpoint(api):
    """The whole reason resolution consults the free inventory first."""
    fake = api(["resend_api_key"])
    with pytest.raises(CredentialError, match="no credential in the vault"):
        creds.resolve_name(Target("root", "ghost"))
    assert all(m == "GET" for m, _, _ in fake.calls), "a read was requested anyway"


def test_an_explicit_override_still_has_to_exist(api):
    """Otherwise --aw-secret becomes a way to make anyone's phone buzz for an
    arbitrary string."""
    api(["private_root_h"])
    with pytest.raises(CredentialError, match="not in the vault"):
        creds.resolve_name(Target("root", "h"), "typo_name")


def test_an_unlinked_workspace_says_so_rather_than_missing_secret(api, monkeypatch):
    monkeypatch.setattr(creds, "request", lambda *a, **k: (503, {"detail": "no cloud link"}))
    with pytest.raises(CredentialError, match="never completed"):
        creds.list_secret_names()


# ── the value ────────────────────────────────────────────────────────────

def test_a_key_is_recognised_by_its_content_not_its_name():
    """One naming convention for both kinds — the value says which it is."""
    assert Credential("anything", KEY).is_private_key
    assert Credential("private_root_h", "hunter2").kind == "password"


def test_fetch_returns_the_value(api):
    api(["private_root_h"])
    assert creds.fetch("private_root_h", "because").value == KEY


def test_a_denial_is_its_own_exception(api):
    """Distinguishable from "no credential": one means stop, the other means
    the lookup was wrong."""
    api(["private_root_h"], read=(403, {"detail": "denied by the human"}))
    with pytest.raises(ApprovalRefused, match="denied"):
        creds.fetch("private_root_h", "because")


def test_a_timeout_says_the_request_is_still_live(api):
    """Telling someone to re-approve is useless if they think it expired."""
    api(["private_root_h"], read=(200, {"status": "pending", "request_id": "x"}))
    with pytest.raises(ApprovalRefused, match="still live"):
        creds.fetch("private_root_h", "because", max_wait_s=0)


def test_the_wait_happens_here_not_inside_one_long_request(api):
    """A command run from an agent-runner container reaches the workspace
    through the tunnel edge, which cuts any request at ~30s. Asking the server
    to hold the connection for five minutes turns a live approval into "502
    workspace offline" — so the POST must ask it to return immediately, and the
    waiting must be a series of short polls."""
    fake = api(["private_root_h"],
               read=(200, {"status": "pending", "request_id": "x"}))
    with pytest.raises(ApprovalRefused):
        creds.fetch("private_root_h", "because", max_wait_s=0)

    post = next(c for c in fake.calls if c[0] == "POST")
    assert post[2]["max_wait_s"] == 0, "asked the server to hold the request open"


def test_a_pending_request_is_polled_by_id_not_re_requested(api, monkeypatch):
    """Re-issuing the read would send a SECOND prompt for a question already on
    the human's screen."""
    monkeypatch.setattr(creds, "POLL_INTERVAL_S", 0)
    fake = _Api(["private_root_h"])
    answers = [(200, {"status": "pending", "request_id": "x"}),
               (200, {"status": "pending", "request_id": "x"}),
               (200, {"status": "approved", "value": KEY})]
    fake.read = answers[0]

    def _request(method, path, body=None, timeout=None):
        fake.calls.append((method, path, body))
        if method == "GET" and "/requests/" in path:
            return answers[min(len(fake.calls) - 1, len(answers) - 1)]
        if method == "GET":
            return 200, {"secrets": [{"name": "private_root_h"}]}
        return answers[0]

    monkeypatch.setattr(creds, "request", _request)
    assert creds.fetch("private_root_h", "because", max_wait_s=30).value == KEY
    assert len([c for c in fake.calls if c[0] == "POST"]) == 1, "prompted twice"


def test_approved_with_no_value_is_not_an_empty_password(api):
    """A spent one-shot grant. Connecting with "" would fail as a bad password
    instead of saying what actually happened."""
    api(["private_root_h"], read=(200, {"status": "approved", "value": None}))
    with pytest.raises(CredentialError, match="already been delivered"):
        creds.fetch("private_root_h", "because")


def test_the_reason_reaches_the_human(api):
    """It is the only thing they see besides the name when deciding."""
    fake = api(["private_root_h"])
    creds.fetch("private_root_h", "deploy the staging release")
    assert fake.calls[-1][2]["reason"] == "deploy the staging release"


# ── the user the name knows ──────────────────────────────────────────────

def test_the_user_is_recovered_from_the_secret_name():
    """``aw-workspace-cli ssh somehost`` finds the key by host and then has to
    log in as somebody. Without this it uses the local account and the server
    rejects a key it would have accepted — a failure that looks like a bad key
    and is not."""
    assert creds.login_user_from_name(
        "private_u888-smwcgrxvnrg3_ssh.example.com", "ssh.example.com") == "u888-smwcgrxvnrg3"
    assert creds.login_user_from_name("ssh_deploy_box", "box") == "deploy"


def test_a_host_wide_name_encodes_no_user():
    """``ssh_box`` genuinely does not say who; inventing one would be a guess
    dressed up as a lookup."""
    assert creds.login_user_from_name("ssh_box", "box") is None


# ── picking up an answer that arrived after we stopped waiting ───────────

def test_an_outstanding_request_is_collected_instead_of_asking_again(api, monkeypatch, tmp_path):
    """The sequence this exists for: the command gives up, the person taps
    twenty minutes later, and running it again used to send a SECOND prompt for
    a question they had already answered."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    from ssh_app import pending
    pending.remember("private_root_h", "old-request")

    fake = api(["private_root_h"], read=(200, {"status": "approved", "value": KEY}))
    assert creds.fetch("private_root_h", "because").value == KEY

    assert not [c for c in fake.calls if c[0] == "POST"], "asked again anyway"
    assert pending.get("private_root_h") is None, "a spent id was left behind"


def test_a_dead_outstanding_request_falls_back_to_asking(api, monkeypatch, tmp_path):
    """An id that expired must not stop the caller getting a connection — they
    wanted a host, not a report on an old request."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    from ssh_app import pending
    pending.remember("private_root_h", "dead")

    calls = []

    def _request(method, path, body=None, timeout=None):
        calls.append((method, path))
        if method == "GET" and "/requests/dead" in path:
            return 200, {"status": "expired"}
        if method == "GET" and "/requests/" in path:
            return 200, {"status": "approved", "value": KEY}
        if method == "GET":
            return 200, {"secrets": [{"name": "private_root_h"}]}
        return 200, {"status": "approved", "value": KEY}

    monkeypatch.setattr(creds, "request", _request)
    assert creds.fetch("private_root_h", "because").value == KEY
    assert any(m == "POST" for m, _ in calls), "never asked for a fresh one"


def test_the_id_is_written_down_before_the_wait_not_after(api, monkeypatch, tmp_path):
    """It has to survive this process giving up — or dying, which is the normal
    end of a per-turn agent container."""
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    from ssh_app import pending
    api(["private_root_h"], read=(200, {"status": "pending", "request_id": "r-1"}))

    with pytest.raises(ApprovalRefused):
        creds.fetch("private_root_h", "because", max_wait_s=0)

    assert pending.get("private_root_h") == "r-1"


def test_a_note_never_holds_a_value(monkeypatch, tmp_path):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path))
    from ssh_app import pending
    pending.remember("private_root_h", "r-1")

    assert KEY not in open(pending.path()).read()
