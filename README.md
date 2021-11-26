# gosig
A CLI for signature creation & verification

# Overview

The CLI is built with the CLI framework [Cobra](https://github.com/spf13/cobra).

The functionallity of the application is implemented with the **go standard library** library.

For the elliptic curve cryptography the [ECDSA P256](https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf) curve is used & for the signature creation / verification the **SHA-256** hash algorithm is used.

## Functionality 

- create an EC Private / Public key-pair.
- create signatures
- verify signatures 

# Build & Run

The application can be built with executing 
```$ go build``` in the root directory of the project, which will build the exectuable ```gosig``` on linux &  ```gosig.exe``` on windows.

# Examples

## Generate a public / private key pair
```
$ gosig genkey id_ec256 # generates id_ec256 & id_ec256.pub in the current direcory
```

## Create a signature 

Create an sample file such as ```test.txt``` and write something in it e.g:
```
$ echo "What a beautiful day!" > test.txt
```

Create the signature!

```
$ gosig create test.txt id_ec256 # creates the file test.txt.sig, which contains the signature
```

## Verify the signature

Verify the signature with:

```
$ gosig verify test.txt test.txt.sig id_ec256.pub` 
```

Exptected output:
```
Valid Signature! :)
```

Now change the ```test.txt``` to an evil message e.g: 
```
$ echo "What a bad day!" > test.txt
```

Verify it again with the command above and you should get the expected output:
```
Invalid Signature! :(
```