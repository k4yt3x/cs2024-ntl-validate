#!/usr/bin/python

import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/validate", methods=["POST"])
def validate():
    # Ensure the request is JSON
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()

    # Validate the presence of 'name' and 'token' in the JSON payload
    if "name" not in data or "token" not in data:
        return jsonify({"error": "JSON must contain 'name' and 'token' fields"}), 400

    name = data["name"].encode("utf-8")  # Convert to bytes for C compatibility
    token = data["token"]

    # Ensure token is an integer
    if not isinstance(token, int):
        return jsonify({"error": "Token must be an integer"}), 400

    # Call the validate_token function
    is_valid = (
        subprocess.run(
            ["./validate", name, str(token)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )

    # Return the result
    return jsonify({"isValid": bool(is_valid)})


def main():
    app.run(debug=True)


if __name__ == "__main__":
    main()
