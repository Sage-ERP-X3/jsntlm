# NTML authentication for node.js

`jsntlm` is a node.js implementation of NTLM authentication.  

This implementation is a free JavaScript adaptation of https://github.com/joval/ntlm-java, which is itself based on https://code.google.com/p/ntlm-java/.

## NTLM protocol

NTLM is a challenge-response authentication protocol which uses three messages to authenticate a client in a connection oriented environment (connectionless is similar),  
and a fourth additional message if integrity is desired.  
First, the client establishes a network path to the server and sends a NEGOTIATE_MESSAGE advertising its capabilities.  
Next, the server responds with CHALLENGE_MESSAGE which is used to establish the identity of the client.  
Finally, the client responds to the challenge with an AUTHENTICATE_MESSAGE.  

See specification in: http://msdn.microsoft.com/en-us/library/cc236621.aspx

## Examples

* [jsntlm/examples/proxyAuthenticator](examples/proxyAuthenticator.md)  
  HTTP request sample with proxy NTLM authentication

## License

Apache 2.0. See [LICENSE.txt](LICENSE.txt).
