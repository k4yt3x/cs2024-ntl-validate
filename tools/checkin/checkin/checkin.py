#!/usr/bin/python

import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/validate", methods=["POST"])
def validate():
    try:
        # ensure the request is JSON
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()

        # validate the presence of 'name' and 'token' in the JSON payload
        if "token" not in data:
            return (
                jsonify({"error": "JSON must contain 'name' and 'token' fields"}),
                400,
            )

        token = data["token"]

        # call the validate_token function
        is_valid = (
            subprocess.run(
                ["../bin/validate", str(token)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )

        # return the result
        return jsonify({"is_valid": bool(is_valid)})
    except Exception:
        return (
            jsonify({"error": "An error occurred. Please notify the administrators."}),
            500,
        )


def main():
    app.run(debug=True)


if __name__ == "__main__":
    main()
