
# NtlmAuthenticator
```javascript
var NtlmAuthenticator = require('jsntlm').NtlmAuthenticator;  
var ntlmAuthentication = new NtlmAuthenticator("myUser", "myPassword", "DOMAIN", options);
```


-------------
## generateNegociateMessage :
``` javascript
var negociateMessage = ntlmAuthentication.generateNegociateMessage();  
```
Generate Negotiate Message and send to other point if this is connection-oriented protocol.  

Returns a base64 encoded String. This will be used to send the negociation message to the server that need NTLM authentication.  


-------------
## generateAuthenticateMessage :
Generate Negotiate Message and send to other point if this is connection-oriented protocol.    
``` javascript
var negociateMessage = ntlmAuthentication.generateAuthenticateMessage(challengeMessage);  
```
The `challengeMessage` parameter is the base64 encoded String received in the server reply in WWW-Authentication header (or Proxy-Authorization header).  

Returns a base64 encoded String. This will be used to send the NTLM authentication to the server.  


-------------
## generateNegociateMessage :
``` javascript
var session = ntlmAuthentication.createSession(options);  
```
Create NTLM session.  

The `options` parameter is optional and can contains the following properties :  
   `connectionType`: All other values​​ that 'connectionOriented' means that you want to use the mode 'connectionless'.  
   `clientChallenge`: Force the client first challenge used to generate the Authenticate Message.  
   `clientChallenge2`: Force the second client challenge used to generate the Authenticate Message.  
   `randomSessionKey` Force the random session key used to generate the Authenticate Message.  
   `timestamp` Force the timestamp used to generate the Authenticate Message.  

