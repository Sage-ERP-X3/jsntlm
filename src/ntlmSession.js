"use strict";
const os = require("os");

exports.NtlmSession = class NtlmSession {
	constructor(options) {
		options = options || {};
		this.host = options.host || os.hostname();
		this.connectionType = options.connectionType || "connectionOriented";
		this.clientChallenge = options.clientChallenge;
		this.clientChallenge2 = options.clientChallenge2;
		this.randomSessionKey = options.randomSessionKey;
		this.timestamp = options.timestamp;
	}
	computeSignature(message) {
		if (!this.seqNum) this.seqNum = 0;
		const mac = this.authenticateMessage.gen.mac(this.authenticateMessage.negotiateFlags, this.seqNum, this.clientSigningKey, this.clientSealingKey, new Buffer(4), message);
		if (this.connectionType === "connectionOriented") {
			this.seqNum++;
		}
		return mac;
	}
};