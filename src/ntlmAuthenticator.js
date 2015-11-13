"use strict";
const NtlmSession = require('./ntlmSession').NtlmSession;
const ntlmMessages = require('./ntlmMessages');
const Type1Message = ntlmMessages.Type1Message;
const Type2Message = ntlmMessages.Type2Message;
const Type3Message = ntlmMessages.Type3Message;

/// !doc
/// 
/// # NtlmAuthenticator
/// ```javascript
/// const NtlmAuthenticator = require('jsntlm').NtlmAuthenticator;  
/// const ntlmAuthentication = new NtlmAuthenticator("myUser", "myPassword", "DOMAIN", options);
/// ```
/// 

exports.NtlmAuthenticator = class NtlmAuthenticator {
	constructor(user, password, domain) {
		this.user = user;
		this.password = password;
		this.domain = domain;

	}
	/// 
	/// -------------
	/// ## generateNegociateMessage :
	/// ``` javascript
	/// const negociateMessage = ntlmAuthentication.generateNegociateMessage();  
	/// ```
	/// Generate Negotiate Message and send to other point if this is connection-oriented protocol.  
	/// 
	/// Returns a base64 encoded String. This will be used to send the negociation message to the server that need NTLM authentication.  
	/// 
	generateNegociateMessage() {
		if (!this.session) throw new Error("NTLM session must be instanciated before generate negociate message.");

		const message = new Type1Message(this.session, this.domain);
		this.session.negociateMessage = message;
		return "NTLM " + message.getResponse();
	}

	/// 
	/// -------------
	/// ## generateAuthenticateMessage :
	/// Generate Negotiate Message and send to other point if this is connection-oriented protocol.    
	///
	/// ``` javascript
	/// const negociateMessage = ntlmAuthentication.generateAuthenticateMessage(challengeMessage);  
	/// ```
	///
	/// The `challengeMessage` parameter is the base64 encoded String received in the server reply in WWW-Authentication header (or Proxy-Authorization header).  
	/// 
	/// Returns a base64 encoded String. This will be used to send the NTLM authentication to the server.  
	/// 
	generateAuthenticateMessage(challenge) {
		if (!challenge) throw new Error("No server challenge provided.");

		if (challenge && challenge.indexOf('NTLM ') !== 0) throw new Error("Server challenge MUST begin with 'NTLM ' characters.");

		this.session.challengeMessage = new Type2Message(challenge.substring(5));
		const message = new Type3Message(this.session, this.user, this.password, this.domain, this.clientChallenge, this.clientChallenge2, this.randomSessionKey, this.timestamp);
		this.session.authenticateMessage = message;
		return "NTLM " + message.getResponse();
	}

	/// 
	/// -------------
	/// ## generateNegociateMessage :
	/// ``` javascript
	/// const session = ntlmAuthentication.createSession(options);  
	/// ```
	/// Create NTLM session.  
	/// 
	/// The `options` parameter is optional and can contains the following properties :  
	///    `connectionType`: All other values​​ that 'connectionOriented' means that you want to use the mode 'connectionless'.  
	///    `clientChallenge`: Force the client first challenge used to generate the Authenticate Message.  
	///    `clientChallenge2`: Force the second client challenge used to generate the Authenticate Message.  
	///    `randomSessionKey` Force the random session key used to generate the Authenticate Message.  
	///    `timestamp` Force the timestamp used to generate the Authenticate Message.  
	/// 
	createSession(options) {
		this.session = new NtlmSession(options);
		return this.session;
	}
};