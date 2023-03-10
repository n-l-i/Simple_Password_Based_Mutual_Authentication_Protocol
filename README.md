# SPBMAP - a Simple Password-Based Mutual Authentication Protocol

 - [Overview](#overview)
     - [Comparisons to other protocols](#overview-comparisons)
     - [Strengths and limitations](#overview-analysis)
 - [Outline](#outline)
     - [Registration](#outline-registration)
     - [Authentication](#outline-authentication)
 - [Definitions](#definitions)
 - [Specification](#specification)
     - [Registration](#specification-registration)
     - [Authentication](#specification-authentication)
 - [Implementation considerations](#implementation)
 - [Test vectors](#testvectors)
     - [Test vector 1](#testvectors-1)

# <a name="overview"> Overview
This document describes a password-based mutual authentication protocol. It provides a way for both the client and the server to authenticate each other and the protocol is relatively simple to implement.

### <a name="overview-comparisons"> Comparisons to other protocols
* **SCRAM**: [SCRAM](https://www.rfc-editor.org/rfc/rfc5802) is a similar protocol but it is a bit more complex. It conforms to both the [SASL](https://www.rfc-editor.org/rfc/rfc4422) and the [GSS-API](https://www.rfc-editor.org/rfc/rfc2743) standards which adds extra complexity and limitations on implementations. SCRAM also authenticates the client first and then authenticates the server whereas SPBMAP authenticates the server first and then the client. The authentication step is also a bit longer for SCRAM than for SPBMAP with 4 messages as compared to 3.

### <a name="overview-analysis"> Strengths and limitations
Strengths:
* The client never has to share their password with the server.

Limitations:
* The client sends a hash of their password to the server during registration.
* The client sends a truncated hash of their password to the server during authentication.
* The server sends a hash of the password to any client providing the correct truncated hash.

Possible attacks:
1. A malicious server would during registration receive a hash of the password. Using this value, one could perform a dictionary or brute-force attack to try and find the original password. A strong password in combination with a strong client-side hash function makes this attack infeasible.
2. A malicious server would during authentication receive a truncated hash of the password. This value enables the same types of attacks as in point number 1, except that the attacker could only hope to narrow down the list of possible passwords and would not be able to figure out the correct password from this value alone.
3. A malicious client could guess the correct truncated hash and would then receive a hash of the password. The chance of correctly guessing the correct truncated hash value is one in 2^20, which is roughly one in a million. Correctly guessing this value and receiving a server-side hash of the password enables the same types of attacks as in point number 1, except that the server-side hash function has also been used to produce the value which slows down the attacker further.

# <a name="outline"> Protocol outline
This section provides a rough outline of how this protocol functions. The sections
[Definitions](#definitions) and [Specification](#specification) describes the protocol in further detail.

### <a name="outline-registration"> Registration
The registration step consists of only one message: a request from the client.

* The client calculates a hash of their password and then sends their id and the password hash to the server.

Depiction of the information flow:
~~~
    Client                                    Server
    ------------------------------------------------
                registration request
             ------------------------->
   -------------------------------------------------
~~~

### <a name="outline-authentication"> Authentication
The authentication step consists of three messages: a request from the client, a response from the server that establishes mutual
challenges and provides the server response to this challenge, and lastly a response to this challenge from the client.

* The client calculates the hash of their password and generates a challenge nonce. The client calculates a truncated signature of their password hash. The client then sends their id, truncated signature, and the nonce to the server.
* The server generates a challenge nonce and calculates its response to the mutual challenge. The server then sends the nonce, its challenge response, and the server side hashing parameters to the client.
* The client calculates the server side hash of the password and uses it to calculate its response to the mutual challenge. The client then sends its challenge response to the server.

When the server challenge response has been received by the client, they make sure that it matches the expected value. If it does, the server is authenticated. The server authenticates the client in the same way when it receives the client challenge response.

Depiction of the information flow:
~~~
    Client                                    Server
    ------------------------------------------------
                challenge request
             ------------------------->
                authentication response
             <-------------------------
                challenge response
             ------------------------->
   -------------------------------------------------
~~~

# <a name="definitions"> Definitions
There are a number of functions and values used in this protocol. These are defined in this section.

### Functions:
* `H_client`: The hash function used by the client.
* `H_server`: The hash function used by the server.
* `HMAC`: The HMAC-SHA-256 algorithm.

### Generated values:
* `id`: The client identifier.
* `password`: The client password.
* `client_salt`: The salt used by the client.
* `server_salt`: The salt used by the server.
* `client_nonce`: Nonce generated by the client.
* `server_nonce`: Nonce generated by the server.
* `client_timestamp`: Timestamp generated by the client.

### Derived values:
* `client_key := H_client(password,client_salt)`
* <code>short_client_key := HMAC(client_key,id) % 2<sup>20</sup></code>
* <code>short_client_signature := HMAC(short_client_key,"client"+client_nonce+"timestamp"+client_timestamp)</code>
* `server_key := H_server(client_key,server_salt)`
* `client_signature := HMAC(server_key,"client"+client_nonce+"server"+server_nonce)`
* `server_signature := HMAC(server_key,"server"+server_nonce+"client"+client_nonce)`

### Data formats:
* All byte string values are encoded as hexadecimal strings.
* Text string values are first encoded in UTF-8 and integers are encoded as big-endian.
* If a byte string is shorter than 32 bytes, the string is prefixed with zeroes to make it 32 bytes long.
* If a byte string is longer than 32 bytes, the SHA-256 digest of the UTF-8 encoded string is used instead.
* Message parameters are sent as JSON using the field names as defined in this document.
* **Example 1**: `123 => "0x000000000000000000000000000000000000000000000000000000000000007b"`.
* **Example 2**: `"abc" => "0x0000000000000000000000000000000000000000000000000000000000616263"`.
* **Example 3**: `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" => "0x3964294b664613798d1a477eb8ad02118b48d0c5738c427613202f2ed123b5f1"`.

# <a name="specification"> Specification
This section describes the communication between the server and the client in further detail.

### <a name="specification-registration"> Registration
Before the registration step, the client has `id`, `password`, `client_salt`, `H_client` and `H_server`. The server has `H_server`.

The registration proceeds as follows:

1.  The client calculates `client_key`.
2.  The client sends `id` and `client_key` to the server.
3.  The server asserts that `id` is not already registered in the database.
4.  The server generates `server_salt`.
5.  The server calculates `server_key` and `short_client_key`.
6.  The server stores `id`, `server_key`, `short_client_key`, and `server_salt`.

Registration can fail at step 3 causing error A.

### <a name="specification-authentication"> Authentication
Before the authentication step, the client has `id`, `password`, `client_salt`, `H_client` and `H_server`. The server has `id`, `server_id_salt`, `server_salt`, `H_server`, `hashed_client_key`, and `hashed_server_key`.

The registration proceeds as follows:
1.  The client generates `client_nonce` and `client_timestamp`.
2.  The client calculates `short_client_signature`.
3.  The client sends `id`, `client_nonce`, `client_timestamp`, and `short_client_signature` to the server.
4.  The server calculates `short_client_signature`.
5.  The server asserts that `id` is registered in the database, that `client_timestamp` is larger than any previously used value, and that `short_client_signature` matches the expected value.
6.  The server generates `server_nonce`.
7.  The server calculates `server_signature`.
8.  The server sends `server_salt`, `server_nonce`, and `server_signature` to the client.
9.  The client calculates `server_key`, `client_signature`, and  `server_signature`.
10. The client asserts that `server_signature` matches the expected value.
11. The client sends `client_signature` to the server.
12. The server calculates `client_signature`.
13. The server asserts that `client_signature` matches the expected value.

Authentication can fail at step 5 causing error B, step 10 causing error C, or step 13 causing error D.

### <a name="specification-errors"> Errors
This section describes how registration and authentication errors should be handled.

* **Error A**: The server responds with the same message as for a successful request.
* **Error B**: The server responds in a way indistinguishable from the response to a successful
request, with incorrect `server_salt` and
`server_signature` instead of the correct values. The incorrect server signature should be randomly
generated. The incorrect salt must be unique but consistent for the
inputs, i.e. every call with an `id` and `client_key` must yield
a different `server_salt` from calls with any other `id` or
`client_key` but the same `server_salt` as previous and subsequent
calls with the same `id` and `client_key`.
* **Error C**: The client aborts the connection.
* **Error D**: The server aborts the connection.

# <a name="implementation"> Implementation considerations
Some points to consider when implementing this protocol are:

* `H_client` and `H_server` should be secure hash functions, for example Scrypt or Argon2 with good settings.
* Both `client_salt` and `server_salt` should be unique to the user and the application.

# <a name="testvectors"> Test vectors
This section lists some test vectors for this protocol.

### <a name="testvectors-1"> Test vector 1
Parameters:
* `H_client(msg,salt) := HMAC(msg,HMAC(salt,"client"))`
* `H_server(msg,salt) := HMAC(msg,HMAC(salt,"server"))`
* `id := "user"`
* `password := "password"`
* `client_salt := "client_salt"`
* `server_salt := "server_salt"`
* `client_nonce := "client_nonce"`
* `server_nonce := "server_nonce"`
* `client_timestamp := 123`

Derived values:
* `client_key = 0xe9e46e87050e8bbd4d5c253cf422a2dce08d3f6435128a5fb85cf46a70b329fd`
* `short_client_key = 0x791c3`
* `short_client_signature = 0x7ead6`
* `server_key = 0x83c5e50916f55b95efa47043142331f89b1832e6c5f878b220679008df73a49f`
* `client_signature = 0xebba3659e3f3c5975b7e0660278fa280ff1f50f8f7bb30b30cc116243c8dc559`
* `server_signature = 0x4721aaa93f334388fcfc9c5e22e91f3e201eecd4da64c2d28b343d6e81059196`
