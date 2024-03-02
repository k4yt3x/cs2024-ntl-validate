# CSides Validate

A reverse engineering challenge written for CyberSCI 2024 Nationals.

## Challenge Background Story

The CSides 2024 conference is approaching. Previously, CSides would simply issue badges bearing the participants' names and then check to see if the name matched their driver's license, without any means to cryptographically verify the badges' authenticity. An insider has revealed that they've upgraded their system this time, implementing a new validation mechanism. Each participant is assigned a token that contains a cryptographic signature of their name. Upon entering the conference, the participant's name on the token is first compared with their ID, and then the token is validated using a secret program. However, just days before the conference, the binary for the validation program was unintentionally leaked due to a DevOps mishap. The binary appears to be highly obfuscated, so surely nobody will be able to decipher the signing process and create valid tokens to gain unauthorized access to the conference...right?
