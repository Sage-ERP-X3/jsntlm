
# Sample httpRequest with NTLM authentication
[See proxyAuthenticator code](proxyAuthenticator.js)  

```javascript
   var proxyAuthenticator = require('jsntlm/examples/proxyAuthenticator');
   var options = {
      host: "proxyserver",
      port: 8080,
      path: "http://www.google.com/",
      headers: {
         Host: "www.google.com"
      }
   };
   var callback = function(response) {
      console.log("RESPONSE STATUS: "+response.statusCode);
      console.log("RESPONSE BODY: "+response.body);
   };
   proxyAuthenticator.httpRequest("DOMAIN", "MyUser", "MyPassword", options, callback);
```

