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
* The client authenticates the server before the server authenticates the client.

Limitations:
* The client sends a hash of their password to the server during registration.
* The client sends a hash of their id to the server during registration an authentication.

Possible attacks:
* With knowledge of the client id, client-side hash function and the client-side hash of the client id, one can perform an attack, for example a brute-force or dictionary attack, to figure out the client salt. Knowing the client salt enables attacks on the hashed password if that is known. This weakness exists because only the salt is then unknown, and this poses a threat since the same salt is used for both the client id and password. A strong hash function combined with a strong salt makes this attack infeasible.
* With knowledge of the the client-side hash of the client id, one can get the server salt by impersonating the client to the server. This poses a threat in the case of a database breach, in which case the server-side hash of a client password could be revealed to an attacker. An attacker could then perform an attack, for example a brute-force or dictionary attack, to figure out the client-side hash of the password. If an attacker also gains knowledge of the client salt then this would enable an attack on the password hash.

# <a name="outline"> Protocol outline
This section provides a rough outline of how this protocol functions. The sections
[Definitions](#definitions) and [Specification](#specification) describes the protocol in further detail.

### <a name="outline-registration"> Registration
The registration step consists of only one message: a request from the client.

* The client calculates hashes of their id and password using a salt and then sends their id, hashed id, and hashed password to the server.
* The server responds with an acknowledgement that it has received the registration request.

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

* The client calculates the hash of its id using a salt and generates a challenge nonce. The client then sends their id, hashed id, and the nonce to the server.
* The server generates a challenge nonce and calculates its response to the mutual challenge. The server then sends the nonce, its challenge response,
and the server side hashing parameters to the client.
* The client calculates the server side hash of the password and uses it to calculate its response to the mutual challenge. The client then sends its
challenge response to the server.

When the server challenge response has been received by the client, they make sure that it matches the expected value. If it does, the server is authenticated. The server authenticates the client in the same way when it receives the client challenge response.

Depiction of the information flow:
~~~
    Client                                    Server
    ------------------------------------------------
                authentication request
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
* `server_id_salt`: The salt used by the server for the id field.
* `server_password_salt`: The salt used by the server for the password field.
* `client_nonce`: Nonce generated by the client.
* `server_nonce`: Nonce generated by the server.

### Derived values:
* `hashed_id := H_client(id,HMAC(client_salt,"id salt"))`
* `hashed_password := H_client(password,HMAC(client_salt,"password salt"))`
* `double_hashed_id := H_server(hashed_id,server_id_salt)`
* `double_hashed_password := H_server(hashed_password,server_password_salt)`
* `client_signature := HMAC(HMAC(double_hashed_password,client_nonce),server_nonce)`
* `server_signature := HMAC(HMAC(double_hashed_password,server_nonce),client_nonce)`

### Data formats:
* All byte string values are encoded as hexadecimal strings. Text string values are first encoded in UTF-8.
* If a string is shorter than 64 bytes, the string is prefixed with zeroes to make it 64 bytes long.
* If a string is longer than 64 bytes, the SHA-256 digest of the UTF-8 encoded string is used instead.
* Message parameters are sent as JSON using the field names as defined in this document.

# <a name="specification"> Specification
This section describes the communication between the server and the client in further detail.

### <a name="specification-registration"> Registration
Before the registration step, the client has `id`, `password`, `client_salt`, `H_client` and `H_server`. The server has `H_server`.

The registration proceeds as follows:

1.  The client calculates `hashed_id` and `hashed_password`.
2.  The client sends `id`, `hashed_id` and `hashed_password` to the server.
3.  The server asserts that `id` is not already registered in the database.
4.  The server generates `server_id_salt` and `server_password_salt`.
5.  The server calculates `double_hashed_id` and `double_hashed_password`.
6.  The server stores `id`, `double_hashed_id`, `double_hashed_password`, `server_id_salt`, and `server_password_salt`.

Registration can fail at step 3 causing error A.

### <a name="specification-authentication"> Authentication
Before the authentication step, the client has `id`, `password`, `client_salt`, `H_client` and `H_server`. The server has `id`, `server_id_salt`, `server_password_salt`, `H_server`, `double_hashed_id`, and `double_hashed_password`.

The registration proceeds as follows:
1.  The client calculates `hashed_id`.
2.  The client generates `client_nonce`.
3.  The client sends `id`, `hashed_id` and `client_nonce` to the server.
4.  The server asserts that `id` is registered in the database.
5.  The server calculates `double_hashed_id`.
6.  The server asserts that `double_hashed_id` matches the value registered at sign up.
7.  The server generates `server_nonce`.
8.  The server calculates `server_signature`.
9.  The server sends `server_password_salt`, `server_nonce`, and `server_signature` to the client.
10. The client calculates `hashed_password`, `double_hashed_password`, `client_signature`, and  `server_signature`.
11. The client asserts that `server_signature` matches the value sent by the server.
12. The client sends `client_signature` to the server.
13. The server calculates `client_signature`.
14. The server asserts that `client_signature` matches the value sent by the client.

Authentication can fail at step 4 or 6 causing error B, step 11 causing error C, or step 14 causing error D.

### <a name="specification-errors"> Errors
This section describes how registration and authentication errors should be handled.

* **Error A**: The server responds with the same message as for a successful request.
* **Error B**: The server responds in a way indistinguishable from the response to a successful
request, with incorrect `server_password_salt` and
`server_signature` instead of the correct values. The incorrect server signature should be randomly
generated. The incorrect salt must be unique but consistent for the
inputs, i.e. every call with an `id` and `hashed_id` must yield
a different `server_password_salt` from calls with any other `id` or
`hashed_id` but the same `server_password_salt` as previous and subsequent
calls with the same `id` and `hashed_id`.
* **Error C**: The client aborts the connection.
* **Error D**: The server aborts the connection.

# <a name="implementation"> Implementation considerations
Some points to consider when implementing this protocol are:

* `client_salt` should not be known by the server or potential attackers.
* `server_id_salt` and `server_password_salt` should be two different values.
* `H_client` and `H_server` should be secure hash functions, for example Scrypt or Argon2.

# <a name="testvectors"> Test vectors
This section lists some test vectors for this protocol.

### <a name="testvectors-1"> Test vector 1
Parameters:
* `H_client(msg,salt) := HMAC(msg,HMAC(salt,"client"))`
* `H_server(msg,salt) := HMAC(msg,HMAC(salt,"server"))`
* `id := "user"`
* `password := "password"`
* `client_salt := "client_salt"`
* `server_id_salt := "server_id_salt"`
* `server_password_salt := "server_password_salt"`
* `client_nonce := "client_nonce"`
* `server_nonce := "server_nonce"`

Derived values:
* `hashed_id = 0xf342012bfeac5cadb51b6abc2e43eea78ccca38fef489c79af6df4f745f86d50`
* `hashed_password = 0x52bed9a45da1514a8df363e155fba142ff98e748df8c3e308998b3183d72a6c6`
* `double_hashed_id = 0xec003d5df24596c6b4a9dc120d35656a8f2b7b75f1f47b6f80d81a59f87fd3d4`
* `double_hashed_password = 0x684895f46d22bb595cc7da0ff2b410f355bbb7ce4cdafd68522dd17932a7d847`
* `client_signature = 0x2faf6c24e060e3021c700b5fdbe7df6d4d508088048c8a23a9b028a1b263ce78`
* `server_signature = 0xd7f3726a2ec3721093c9eef5f14e777512e99080b3b0f62c1af56ad1f228edf8`
