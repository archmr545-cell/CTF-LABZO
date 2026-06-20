from flask import Flask, request, jsonify
import hashlib
import time

app = Flask(__name__)

# Demo hashed flags (SHA-256 of the plaintext flag)
# NOTE: Replace these hashes with the real ones if you want different flags.
HASHED_FLAGS = {
    1: "6d6be3a5d6d3d3b7cdb1f4ed6af2c2a4dbb5d4e4e6d3b2f3b4f1f4c2a0a8c2d0",
    2: "b3c6a6a9b0f5c0a1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
    3: "0f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
    4: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
}

DUMMY_DB = {
    "users": []
}

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

# Very simple rate limiter (HTB-like friction)
FAILS = {}
MAX_FAILS = 5
WINDOW_SEC = 60


def now():
    return time.time()


@app.post('/api/check')
def api_check():
    data = request.get_json(silent=True) or {}
    cid = int(data.get('id', 0))
    flag = str(data.get('flag', ''))

    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'local'
    k = (ip, cid)
    rec = FAILS.get(k)

    if rec and (now() - rec['t0']) < WINDOW_SEC and rec['fails'] >= MAX_FAILS:
        return jsonify({"ok": False, "msg": "Rate limited. Coba lagi nanti."}), 429

    # reset window if expired
    if rec and (now() - rec['t0']) >= WINDOW_SEC:
        rec = None

    expected = HASHED_FLAGS.get(cid)
    if not expected:
        return jsonify({"ok": False, "msg": "Challenge tidak ada."}), 400

    got = sha256_hex(flag.strip())
    if got == expected:
        if rec:
            FAILS.pop(k, None)
        return jsonify({"ok": True, "msg": "Benar ✅"})

    if not rec:
        FAILS[k] = {'t0': now(), 'fails': 1}
    else:
        rec['fails'] += 1

    return jsonify({"ok": False, "msg": "Salah ❌"}), 200


@app.get('/api/sqli-lab')
def sqli_lab():
    # Hard fail-safe endpoint just to provide content
    # Real SQLi challenge is simulated client-side for safety.
    return jsonify({
        "hint": "Kamu mau bikin request yang 'mirip SQLi'. Tapi server ini tidak melakukan query SQL sungguhan. Fokus latihan validasi & rate limit." 
    })


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)

