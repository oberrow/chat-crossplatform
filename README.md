# Description
chat server coded in c
# How to use
## Server:<br></br>
Open a command prompt window in the directory that chat_server is in
`C:/chat_server>`
<br>Type in chat_server
<br>`C:/chat_server>chat_server`
<br>Click enter
<br>It will crash
<br>To fix the crash type `chat_server --make_salt`
<br>`C:/chat_server/chat_server --make_salt`
<br>Type in chat_server again
<br>`C:/chat_server/chat_server`
<br>You will see that it says 'Listening on port 443!'
```
C:/chat_server>chat_server
Listening on port 443!
```
It binds to the ip localhost:443 by default if you want to change that then use the command line argument --ip <br> Syntax: `--ip [ip address to bind to]`<br> Notes: The ip **must** be in numerical form (eg. 163.445.91.34)
<br>To change the port it binds to use the command line argument --port<br>Syntax: `--port [port to bind to]`
<br>Use `--help` or `-h` for more command line arguments
<br>**NOTE** You **must** have an ssl certificate and private key to use this and both of the files **must** be in .pem format and the files should be in the same directory as the server executable
### Example:
`C:/chat_server>chat_server --ip 123.456.78.9 --port 12345`
# The Chat Protocol
## Intial connection:
### Inital Message
<br>The client sends it's protocol version and the server checks it to see if it matches
### Response
<br>An error code will be sent if the check fails
<br>If the client protocol version > then the server protocol version then it sends `CHAT_ERROR_SERVER_VERSION_OUTDATED (-60001)`
<br>If the client protocol version < then the server protocol version then it sends `CHAT_ERROR_CLIENT_VERSION_OUTDATED (-60000)`
<br>Otherwise, it will send `CHAT_PROTOCOL_VERSION_MATCH` and the connection can proceed.
## Signing in
### Inital Message
When the client wants to sign in it sends `CHAT_PROTOCOL_SIGNIN` and then the server will wait for the username and the password.
<br>The client will then send the username and password and the server will compare the hashed value of the password to the hashed password in the database.
### Response
If the sign in suceeds the server will send `CHAT_PROTOCOL_AUTHENTICATED`.
Otherwise an error code is sent.
`CHAT_PROTOCOL_INVALID_PASSWORD` is sent when the user exists but the password is incorrect.
`CHAT_PROTOCOL_DOESNT_EXIST` is sent when no user exists with the username.
## Signing up
### Inital Message
When the client wants to sign up for a new account it sends `CHAT_PROTOCOL_SIGNUP` and then the server will wait for the username and password
<br>The client will then send the username and password and the server will attempt to make a new account with that username.
### Response
If the sign up suceeds no message will be sent by the server.
Otherwise, an error message is sent.
`CHAT_PROTOCOL_ALREADY_EXISTS` is sent when the account you are attempting to create already exists.
## Other info about the protocol will be listed below
## Format: MSG -> RESPONSE(s) -> Parameter(s) -> Notes
<br>CHAT_PROTOCOL_SHUTDOWN        -> No Response -> No Parameters -> Shut's down the connection allowing no communication
<br>CHAT_PROTOCOL_WHOAMI          -> Connected Client Username -> No Parameters -> N.A.
<br>CHAT_PROTOCOL_LISTONLINEUSERS -> Loops through all the connected clients username and sends them one by one -> No Parameters -> N.A.
<br>CHAT_PROTOCOL_REMOVE          -> CHAT_PROTOCOL_AUTHENTICATED, CHAT_PROTOCOL_INVALID_PASSWORD -> client password -> It will close the connection once the deletion completed sucessfully.
<br>CHAT_PROTOCOL_CHANGE_PWD      -> CHAT_PROTOCOL_AUTHENTICATED, CHAT_PROTOCOL_INVALID_PASSWORD -> client password -> Unlike CHAT_PROTOCOL_REMOVE it will keep the connection open once it's done changing the password. If there are other accounts currently signed in then it will not kick them
<br>CHAT_PROTOCOL_KICKUSER        -> CHAT_PROTOCOL_ACCESS_DENIED -> target username -> If the client was able to use an old version of the chat protocol then the message that the server sends when a user is kicked (CHAT_PROTOCOL_KICKED) will be ignored and the user will stay on.
