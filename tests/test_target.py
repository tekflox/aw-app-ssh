"""Argv parsing — the part that decides whose phone rings.

Everything downstream is keyed on what comes out of here, so these pin the
cases where a naive parser picks the wrong word: a flag's value that looks like
a host, a remote command that contains another host, and the difference between
"no user was named" and "the user is empty".
"""
from __future__ import annotations

from ssh_app.target import Target, parse_rsync, parse_ssh, ssh_target_index


# ── ssh ──────────────────────────────────────────────────────────────────

def test_plain_target():
    assert parse_ssh(["root@host"]) == Target("root", "host", None)


def test_a_host_with_no_user_is_not_a_user_of_empty_string():
    """None means "the argv never said", which is what lets the resolver fall
    back to finding a credential by host. An empty string would build the
    secret name ``private__host`` and ask for something that cannot exist."""
    assert parse_ssh(["host"]).user is None


def test_flag_values_are_not_mistaken_for_the_target():
    """``-o`` eats the next word. Reading ``User=root`` as a hostname would
    request a credential for a host nobody named."""
    t = parse_ssh(["-o", "User=root", "-i", "somekey", "realhost"])
    assert t.host == "realhost"
    assert t.user == "root"  # -o User= is authoritative


def test_boolean_flags_do_not_swallow_the_target():
    """``-f`` in ssh takes no value. Listing it among the value-taking flags
    would make ``ssh -f host`` resolve to nothing."""
    assert parse_ssh(["-f", "-q", "-4", "host"]).host == "host"


def test_the_remote_command_is_not_a_second_target():
    """``ssh a ssh b`` connects to a. Taking b as well would ask a second
    person for a key to run a string this command never interprets."""
    assert parse_ssh(["root@a", "ssh", "root@b"]).host == "a"


def test_dash_l_overrides_the_bare_host():
    assert parse_ssh(["-l", "deploy", "host"]).user == "deploy"
    assert parse_ssh(["-ldeploy", "host"]).user == "deploy"


def test_port_is_picked_up_glued_or_separate():
    assert parse_ssh(["-p", "2222", "root@host"]).port == 2222
    assert parse_ssh(["-p2222", "root@host"]).port == 2222


def test_ssh_uri_form():
    t = parse_ssh(["ssh://deploy@host:2222/"])
    assert (t.user, t.host, t.port) == ("deploy", "host", 2222)


def test_no_target_at_all():
    assert parse_ssh(["-V"]) is None


def test_target_index_points_at_the_host():
    """Injected options must land immediately before the host: ssh takes the
    first value for an option, so ours have to come after the caller's, and
    ssh refuses options that appear after the target."""
    args = ["-v", "-p", "22", "root@host", "uptime"]
    assert ssh_target_index(args) == 3


# ── rsync ────────────────────────────────────────────────────────────────

def test_remote_source():
    assert parse_rsync(["-avz", "user@host:/srv/", "./local/"]) == Target("user", "host")


def test_remote_destination():
    assert parse_rsync(["-avz", "./local/", "user@host:/srv/"]) == Target("user", "host")


def test_both_sides_local_has_no_target():
    """Nothing to authenticate — the command should say so rather than resolve
    a credential for a transfer that never leaves the machine."""
    assert parse_rsync(["-a", "./a/", "./b/"]) is None


def test_rsync_dash_e_value_is_not_a_target():
    """``-e 'ssh -p 2222'`` is the transport, not a host."""
    assert parse_rsync(["-e", "ssh -p 2222", "user@host:/x", "./y"]).host == "host"


def test_a_bare_word_is_not_an_rsync_target_without_a_colon():
    """rsync's remote side always has a colon; ``./backup`` is a local path."""
    assert parse_rsync(["-a", "backup", "user@host:/x"]).host == "host"
