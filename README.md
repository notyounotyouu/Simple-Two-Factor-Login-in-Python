# Simple Two Factor Login in Python

Nithin Kumaran (C00313547), SE606, South East Technological University, Carlow

A small Flask app that adds a TOTP second step (RFC 6238) to a password login.
It works with Google Authenticator.

## What it does

* Sign up with a username and password. The password is hashed with bcrypt.
* Shows a QR code to scan with Google Authenticator.
* Login asks for the password, then the six digit code.
* Rejects wrong, expired and reused codes.
* Locks the account after five wrong codes in a row.
* A live demo page shows the QR code, the server's code and a countdown.

## Files

| File | Purpose |
| --- | --- |
| `app.py` | The Flask app and all the login logic |
| `templates/` | The HTML pages |
| `test_twofactor.py` | Automated pytest cases |
| `requirements.txt` | Libraries to install |

## Run it

```
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Test it

```
pytest -v
```

## Note

This is a teaching project. Use test accounts only. The demo page shows the
secret and the live code on purpose, which a real site must never do.
