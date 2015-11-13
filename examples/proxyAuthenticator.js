"use strict";

var NtlmAuthenticator = require('jsntlm/lib/ntlmAuthenticator').NtlmAuthenticator;
var http = require('http');
var assert = require('assert');

/// !doc
/// 
/// # Sample httpRequest with NTLM authentication
///
/// [See proxyAuthenticator code](proxyAuthenticator.js)  
/// 
/// ```javascript
///    var proxyAuthenticator = require('jsntlm/examples/proxyAuthenticator');
///    var options = {
///       host: "proxyserver",
///       port: 8080,
///       path: "http://www.google.com/",
///       headers: {
///          Host: "www.google.com"
///       }
///    };
///    var callback = function(response) {
///       console.log("RESPONSE STATUS: "+response.statusCode);
///       console.log("RESPONSE BODY: "+response.body);
///    };
///    proxyAuthenticator.httpRequest("DOMAIN", "MyUser", "MyPassword", options, callback);
/// ```
/// 
exports.httpRequest = function(domain, user, password, options, callback) {
	var ntlmAuthentication = new NtlmAuthenticator(user, password, domain);
	// Create NTLM session
	ntlmAuthentication.createSession();
	var negociateMsg = ntlmAuthentication.generateNegociateMessage();

	// Necessary to use only one TCP Stream for the two requests
	options.agent = new http.Agent();
	options.agent.maxSockets = 1;

	// Set header properties
	options.headers["Proxy-Connection"] = "Keep-Alive";
	options.headers["Proxy-Authorization"] = negociateMsg;

	var _negociateRequest = http.request(options, function(negResult) {

		negResult.setEncoding('utf8');
		negResult.on('data', function() {});
		negResult.on('end', function() {
			assert.equal(negResult.statusCode, 407, "Negociate status code 407 OK");
			var srvChallenge = negResult.headers["proxy-authenticate"];

			var cookie = negResult.headers["set-cookie"];
			options.headers.cookie += "; " + cookie;

			var authenticateMsg = ntlmAuthentication.generateAuthenticateMessage(srvChallenge);
			options.headers["Proxy-Authorization"] = authenticateMsg;

			var _authenticateRequest = http.request(options, function(authResult) {

				authResult.on('data', function(chunk) {
					authResult.body += chunk;
				});
				authResult.on('end', function() {
					//assert.equal(authResult.statusCode, 200, "Authenticate status code 200 OK");
					callback(authResult);

				});

			});
			_authenticateRequest.on('error', function(e) {
				throw new Error('A problem occured with NTLM Authenticate request: ' + e.message);
			});
			_authenticateRequest.end();
			return;
		});
	});
	_negociateRequest.on('error', function(e) {
		throw new Error('A problem occured with NTLM Negociate request: ' + e.message);
	});

	console.log("Send authenticate request");
	_negociateRequest.end();
};