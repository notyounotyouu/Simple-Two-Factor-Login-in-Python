"""
Automated tests for the two factor login (Item #7).

Run with:  pytest -v

Test 1  20 codes match an independent RFC 6238 implementation, which is the
        algorithm Google Authenticator runs.
Test 2  30 bad codes are rejected (10 wrong, 10 expired, 10 reused).
Test 3  The account locks after five wrong codes in a row.
"""

import base64
import hashlib
import hmac
import random
import struct
import time

import pyotp
import pytest

import app as twofactor

PASSWORD = "test-password-1"


@pytest.fixture(autouse=True)
def fresh_database(tmp_path):
    """Every test gets its own empty database file."""
    twofactor.app.config["DATABASE"] = str(tmp_path / "test.db")
    twofactor.app.config["TESTING"] = True
    twofactor.init_db()


def new_user(name="alice"):
    """Create a test account and return its secret."""
    return twofactor.create_user(name, PASSWORD)


def reference_totp(secret, for_time, digits=6, step=30):
    """
    TOTP written from RFC 6238 and RFC 4226 with the standard library only.
    It does not use PyOTP, so it is an independent check of the app's codes.
    """
    key = base64.b32decode(secret, casefold=True)
    counter = struct.pack(">Q", int(for_time) // step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** digits).zfill(digits)


# ------------------------------------------------ Test 1. codes match (20)

@pytest.mark.parametrize("try_number", range(1, 21))
def test_code_matches_reference(try_number):
    """The app accepts the code an independent TOTP generator produces."""
    secret = new_user()
    now = time.time() + try_number * 30          # 20 different time steps
    code = reference_totp(secret, now)

    assert pyotp.TOTP(secret).at(now) == code    # same code on both sides
    ok, message = twofactor.login("alice", PASSWORD, code, now)
    assert ok, message


RFC_6238_VECTORS = [            # Appendix B of RFC 6238, SHA1, 8 digits
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("for_time, expected", RFC_6238_VECTORS)
def test_rfc_6238_vectors(for_time, expected):
    """PyOTP and the reference both give the official RFC test values."""
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert pyotp.TOTP(secret, digits=8).at(for_time) == expected
    assert reference_totp(secret, for_time, digits=8) == expected


# ---------------------------------------------- Test 2. bad codes (30)

@pytest.mark.parametrize("try_number", range(1, 11))
def test_wrong_code_rejected(try_number):
    """A random six digit code that is not valid right now is rejected."""
    secret = new_user()
    now = time.time()
    totp = pyotp.TOTP(secret)
    valid = {totp.at(now, counter_offset=o) for o in (-1, 0, 1)}

    rng = random.Random(try_number)
    code = f"{rng.randrange(1000000):06d}"
    while code in valid:
        code = f"{rng.randrange(1000000):06d}"

    ok, message = twofactor.login("alice", PASSWORD, code, now)
    assert not ok


@pytest.mark.parametrize("steps_old", range(2, 12))
def test_expired_code_rejected(steps_old):
    """A real code from 1 to 5.5 minutes ago is outside the window."""
    secret = new_user()
    now = time.time()
    totp = pyotp.TOTP(secret)
    old_code = totp.at(now - steps_old * 30)
    valid = {totp.at(now, counter_offset=o) for o in (-1, 0, 1)}
    if old_code in valid:
        pytest.skip("old code equals a current code by chance")

    ok, message = twofactor.login("alice", PASSWORD, old_code, now)
    assert not ok


@pytest.mark.parametrize("try_number", range(1, 11))
def test_reused_code_rejected(try_number):
    """A code works once. The same code a second time is rejected."""
    secret = new_user()
    now = time.time() + try_number * 30
    code = pyotp.TOTP(secret).at(now)

    first, message = twofactor.login("alice", PASSWORD, code, now)
    assert first, message
    second, message = twofactor.login("alice", PASSWORD, code, now + 1)
    assert not second
    assert "already been used" in message


# ---------------------------------------------- Test 3. lockout

def wrong_code(secret, now):
    """Return a six digit code that is not valid at this time."""
    totp = pyotp.TOTP(secret)
    valid = {totp.at(now, counter_offset=o) for o in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333")
                if c not in valid)


def test_account_locks_after_five_wrong_codes():
    secret = new_user()
    now = time.time()
    bad = wrong_code(secret, now)

    for attempt in range(1, 5):                      # four wrong codes
        ok, message = twofactor.login("alice", PASSWORD, bad, now)
        assert not ok
        assert not twofactor.get_user("alice")["locked"]

    ok, message = twofactor.login("alice", PASSWORD, bad, now)   # the fifth
    assert not ok
    assert twofactor.get_user("alice")["locked"]

    # a correct password and a correct code no longer get in
    good = pyotp.TOTP(secret).at(now)
    ok, message = twofactor.login("alice", PASSWORD, good, now)
    assert not ok
    assert "locked" in message


def test_good_login_resets_fail_count():
    secret = new_user()
    now = time.time()
    bad = wrong_code(secret, now)

    for attempt in range(4):
        twofactor.login("alice", PASSWORD, bad, now)
    assert twofactor.get_user("alice")["fail_count"] == 4

    ok, message = twofactor.login("alice", PASSWORD,
                                  pyotp.TOTP(secret).at(now), now)
    assert ok
    assert twofactor.get_user("alice")["fail_count"] == 0


# ---------------------------------------------- Extra checks

def test_one_step_window_allows_small_clock_gap():
    """Codes from the step before and the step after are accepted."""
    secret = new_user()
    now = time.time()
    totp = pyotp.TOTP(secret)
    assert twofactor.matching_step(secret, totp.at(now - 30), now) is not None
    assert twofactor.matching_step(secret, totp.at(now + 30), now) is not None


def test_wrong_password_rejected_even_with_good_code():
    secret = new_user()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    ok, message = twofactor.login("alice", "not-the-password", code, now)
    assert not ok


def test_password_is_stored_as_bcrypt_hash():
    new_user()
    stored = twofactor.get_user("alice")["password_hash"]
    assert stored.startswith(b"$2")
    assert PASSWORD.encode() not in stored


def test_qr_link_follows_otpauth_format():
    secret = new_user()
    link, image = twofactor.make_qr("alice", secret)
    assert link.startswith("otpauth://totp/")
    assert f"secret={secret}" in link
    assert image.startswith("data:image/png;base64,")


def test_web_flow_sign_up_setup_login():
    """Drive the real pages. Sign up, confirm setup, then log in."""
    client = twofactor.app.test_client()
    client.post("/signup", data={"username": "bob", "password": PASSWORD})
    secret = twofactor.get_user("bob")["secret"]

    page = client.get("/setup")
    assert secret.encode() in page.data

    code = pyotp.TOTP(secret).now()
    reply = client.post("/setup", data={"code": code})
    assert reply.status_code == 302

    client.post("/login", data={"username": "bob", "password": PASSWORD})

    # the setup code was saved as used, so the same code is refused
    client.post("/login", data={"code": code})
    assert b"Welcome, bob" not in client.get("/").data

    # the next code (one step later) logs the user in
    next_code = pyotp.TOTP(secret).at(time.time() + 30)
    client.post("/login", data={"code": next_code})
    assert b"Welcome, bob" in client.get("/").data
