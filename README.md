# Infinite Free Tickets

A reverse engineering challenge written for the CyberSCI 2024 Nationals competition.

## Challenge Background Story

The CSides 2024 conference is approaching. Previously, CSides would simply issue badges bearing the participants' names and then check to see if the name matched their driver's license, without any means to verify the badges' authenticity. Many participants printed their own badges and saved $1,500 for each ticket. The organizers weren't very happy about this.

An insider has revealed that they've upgraded their system this time, implementing a new validation mechanism. Each participant is given a token that contains a cryptographic signature of their name. Upon entering the conference, the participant's name on the token is first compared with their ID, and then the token is validated using a secret program.

However, just days before the conference, the binary for the validation program was unintentionally leaked due to some DevOps mishap. The binary appears to be obfuscated, so surely nobody will be able to figure out the signing process and create valid tokens to gain free access to the conference...right?

## Instructions

Each token contains the name of the participant and other information required to verify the authenticity of the token. There are multiple stages to this challenge. Completing each stage will grant you a flag.

A few valid tokens have been leaked with the binary, which could be useful for your analysis:

- John Doe: `Sm9obiBEb2U=.CIZlTtWUaGD7XFHRCK/gob2EKpmMYcudT6sWtAOfTynh5RAMx1FXIUJr+Vo43RvG`
- TEST: `VEVTVA==.d3/ErvFXeG78/APAPAnXH+J4QvfYQA6F64XSgSUY9y+Bb9OHzYQmKvELj9soPSfX`

### Stage 1: Finding the Key

There is a cryptographic key **used to sign the tokens** embedded in the binary. Reverse engineer the binary and find the key. The key should be a string in the format of `flag{...}`. Submit the key as the flag directly to CTFd.

### Stage 2: Generating Tokens

Your ultimate goal in this challenge is to understand the signing process and be able to generate valid tokens for any given name. To prove your understanding, you must implement the singing code. An API endpoint will give you 100 random names as a challenge. You must generate valid tokens for all names and submit them. If all of the responses are correct, you will receive the flag. The names will rotate every minute.

**Do not attack the challenge API server.** The server is only used to validate your solution. Attacking it is outside the scope of this challenge.

To help you save some time, a Python template script `solver_template.py` has been provided. You only need to focus on implementing the `generate_token` function, which takes a name as input and returns the token as output. In case you want to implement your own solution from scratch, the API specification is provided in Appendix A.

## Appendix A: API Endpoints

### `GET /challenge`

Returns a JSON object with a list of 100 random names.

#### Response

```json
{
  "names": [
    "Jovani Brakus",
    "Eryn Schuppe",
    "Raphael Wuckert",
    "Jaqueline Stoltenberg",
    ...
  ]
}
```

### `POST /challenge`

Validates the submissions for the challenge. Returns status code 400 with a JSON object with a string field `error` containing an error message if any of the submissions are incorrect. Returns status code 200 with a JSON object with a string field `flag` if all of the submissions are correct.

#### Request

```json
{
  "submissions": [
    {
      "name": "Jovani Brakus",
      "token": "TOKEN"
    },
    {
      "name": "Eryn Schuppe",
      "token": "TOKEN"
    },
    {
      "name": "Raphael Wuckert",
      "token": "TOKEN"
    },
    {
      "name": "Jaqueline Stolenberg",
      "token": "TOKEN"
    },
    ...
  ]
}
```

#### Response

If any of the submissions are incorrect:

```json
{
  "error": "Invalid token for name: Jovani Brakus"
}
```

If all of the submissions are correct:

```json
{
  "message": "All submissions are valid!",
  "flag": "flag{...}"
}
```

### `POST /validate`

Validates a token. This endpoint is used for testing purposes only. Returns a JSON object with a boolean field `valid` indicating whether the token is valid. If the token is invalid, the server returns status code 400. If the token is valid, the server returns status code 200.

#### Request

```json
{
  "token": "Sm9obiBEb2U=.CIZlTtWUaGD7XFHRCK/gob2EKpmMYcudT6sWtAOfTynh5RAMx1FXIUJr+Vo43RvG"
}
```

#### Response

```json
{
  "valid": true
}
```
