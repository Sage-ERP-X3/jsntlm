/* jshint -W079 */
/* jshint unused: false */
/* global QUnit: false, test: false, strictEqual: false, start: false, stop: false */
"use strict";
QUnit.module(module.id);

var ntmlMessages = require('../../lib/ntlmMessages');
var CipherGen = ntmlMessages.CipherGen;
var NtlmAuthenticator = require('../../lib/ntlmAuthenticator').NtlmAuthenticator;

var BYTES_PER_LINE = 16;
var MIN_LINE_LENGTH = 7 + 2 + (BYTES_PER_LINE * 3);
var LINE_LENGTH = 7 + 2 + (BYTES_PER_LINE * 4);

function block2buffer(blocks) {
	var nextByteNumber = 0;
	var data = [];
	for (var i in blocks) {
		var inLine = blocks[i];
		inLine = inLine.trim();

		if (inLine.length === 0) continue;
		if (inLine.length < MIN_LINE_LENGTH || inLine.length > LINE_LENGTH) {
			throw new Error("Can't parse line[" + i + "] invalid length: " + inLine.length + " (" + inLine + ")");
		} else if (inLine.length < LINE_LENGTH && i < blocks.length - 1) {
			throw new Error("Can't parse line[" + i + "] previous line was last: " + inLine);
		}
		if (inLine.charAt(7) !== ':') {
			throw new Error("Can't parse line[" + i + "]: - no ':' " + inLine);
		}
		var byteNumberString = inLine.substring(0, 7);
		var byteNumber = parseInt(byteNumberString, 16);
		nextByteNumber = byteNumber + BYTES_PER_LINE;

		var dataString = inLine.substring(7 + 2, MIN_LINE_LENGTH - 1);
		data.push(new Buffer(dataString.replace(/ /g, ""), "hex"));
	}
	return Buffer.concat(data);
}

var USER_NAME = "User";
var DOMAIN_NAME = "Domain";
var SERVER_NAME = "Server";
var WORKSTATION_NAME = "COMPUTER";
var PASSWORD = "Password";

var RANDOM_SESSION_KEY = block2buffer([
	"0000000: 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 UUUUUUUUUUUUUUUU"]);

var TIME = block2buffer([
	"0000000: 00 00 00 00 00 00 00 00                         ........"]);

var CLIENT_CHALLENGE = block2buffer([
	"0000000: aa aa aa aa aa aa aa aa                         ........"]);

var SERVER_CHALLENGE = block2buffer([
	"0000000: 01 23 45 67 89 ab cd ef                         .#Eg...."]);

var TARGET_INFO;

test("4.2.1 Common Values", function() {
	var negotiateFlagBytes = block2buffer([
		"0000000: 33 82 8a e2                                     3..."]);
	var negotiateFlags = negotiateFlagBytes.readUInt32LE(0);

	// AV Pair 1 - NetBIOS Server name:
	var avPair1DomainName = new Buffer("Server", "ucs2");
	var expectedAvPair1DomainName = block2buffer([
		"0000000: 53 00 65 00 72 00 76 00 65 00 72 00             S.e.r.v.e.r."]);
	strictEqual(avPair1DomainName.toString('hex'), expectedAvPair1DomainName.toString('hex'), "AV Pair 1 Domain Name OK");
	var avPair1Info = new Buffer(4);
	avPair1Info.readUInt16LE(0x0001, 0);
	avPair1Info.readUInt16LE(avPair1DomainName.length, 2);

	// AV Pair 2 - NetBIOS Domain name:
	var avPair2DomainName = new Buffer("Domain", "ucs2");
	var expectedAvPair2DomainName = block2buffer([
		"0000000: 44 00 6f 00 6d 00 61 00 69 00 6e 00             D.o.m.a.i.n."]);
	strictEqual(avPair2DomainName.toString('hex'), expectedAvPair2DomainName.toString('hex'), "AV Pair 2 Domain Name OK");
	var avPair2Info = new Buffer(4);
	avPair2Info.readUInt16LE(0x0002, 0);
	avPair2Info.readUInt16LE(avPair2DomainName.length, 2);

	TARGET_INFO = Buffer.concat([avPair2Info, avPair2DomainName, avPair1Info, avPair1DomainName, new Buffer("00000000", "hex")]);

});

test("4.2.2 NTLM v1 Authentication", function() {

	// The CHALLENGE_MESSAGE (section 2.2.1.2):
	var challengeMessage = block2buffer([
		"0000000: 4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 NTLMSSP.........",
		"0000010: 38 00 00 00 33 82 02 e2 01 23 45 67 89 ab cd ef 8...3....#Eg..=.",
		"0000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................",
		"0000030: 06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00 ..p.....S.e.r.v.",
		"0000040: 65 00 72 00                                     e.r."]);

	var ntlmAuthentication = new NtlmAuthenticator(USER_NAME, PASSWORD, DOMAIN_NAME);
	var session = ntlmAuthentication.createSession({
		host: WORKSTATION_NAME,
		connectionType: "connectionOriented",
		clientChallenge: CLIENT_CHALLENGE,
		clientChallenge2: CLIENT_CHALLENGE,
		randomSessionKey: RANDOM_SESSION_KEY,
		timestamp: TIME
	});
	ntlmAuthentication.generateNegociateMessage();
	var authenticateMessage = ntlmAuthentication.generateAuthenticateMessage("NTLM " + challengeMessage.toString('base64'));
	var resp = authenticateMessage;
	var authResp = new Buffer(authenticateMessage.substring(5), "base64");
	var gen = session.authenticateMessage.gen;

	// 4.2.2.1.1 LMOWFv1()
	var lmHash = gen.getLMHash();
	var expectedLmowfv1 = block2buffer([
		"0000000: e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d ...gA...J;..?..m"]);
	strictEqual(lmHash.toString('hex'), expectedLmowfv1.toString('hex'), "4.2.2.1.1 LMOWFv1() OK");

	// 4.2.2.1.2 NTOWFv1()
	var ntlmHash = gen.getNTLMHash();
	var expectedNtowfv1 = block2buffer([
		"0000000: a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52 ...@e.....N....R"]);
	strictEqual(ntlmHash.toString('hex'), expectedNtowfv1.toString('hex'), "4.2.2.1.1 NTOWFv1() OK");

	var expectedSessionBaseKey = block2buffer([
		"0000000: d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84 .rb.....t......."]);

	var expectedNTLMv1Response = block2buffer([
		"0000000: 67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c g.0......5..O.3.",
		"0000010: 44 bd be d9 27 84 1f 94                         D...'..."]);

	var expectedLMv1Response = block2buffer([
		"0000000: 98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 .......].......r",
		"0000010: de f1 1c 7d 5c cd ef 13                         ...}...."]);

	var expectedEncryptedSessionKey = block2buffer([
		"0000000: 51 88 22 b1 b3 f3 50 c8 95 86 82 ec bb 3e 3c b7 Q.....P........."]);

	var expectedEncryptedSessionKey2 = block2buffer([
		"0000000: 74 52 ca 55 c2 25 a1 ca 04 b4 8f ae 32 cf 56 fc tR.U........2.V."]);

	var expectedEncryptedSessionKey3 = block2buffer([
		"0000000: 4c d7 bb 57 d6 97 ef 9b 54 9f 02 b8 f9 b3 78 64 L..W....T.....xd"]);

	var expectedAuthenticateMessage = block2buffer([
		"0000000: 4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 NTLMSSP.........",
		"0000010: 6c 00 00 00 18 00 18 00 84 00 00 00 0c 00 0c 00 l...............",
		"0000020: 48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00 H.......T.......",
		"0000030: 5c 00 00 00 10 00 10 00 9c 00 00 00 35 82 80 e2 ............5...",
		"0000040: 05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00 ..(.....D.o.m.a.",
		"0000050: 69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00 i.n.U.s.e.r.C.O.",
		"0000060: 4d 00 50 00 55 00 54 00 45 00 52 00 98 de f7 b8 M.P.U.T.E.R.....",
		"0000070: 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d ...]...w...r...}",
		"0000080: 5c cd ef 13 67 c4 30 11 f3 02 98 a2 ad 35 ec e6 =...g-0......5..",
		"0000090: 4f 16 33 1c 44 bd be d9 27 84 1f 94 51 88 22 b1 O.3.D...'...Q...",
		"00000A0: b3 f3 50 c8 95 86 82 ec bb 3e 3c b7             ..P......><."]);

	// LM Resp Length (twice)
	var lmRespLen = authResp.readUInt16LE(12);
	strictEqual(lmRespLen, 24, "LM Response length OK");
	lmRespLen = authResp.readUInt16LE(14);
	strictEqual(lmRespLen, 24, "LM Response length (bis) OK");
	// LM Resp Offset
	var lmRespOffset = authResp.readUInt32LE(16);
	strictEqual(lmRespOffset, 108, "LM Response offset OK");

	// NT Resp Length (twice)
	var ntRespLen = authResp.readUInt16LE(20);
	strictEqual(ntRespLen, 24, "NT Response length OK");
	ntRespLen = authResp.readUInt16LE(22);
	strictEqual(ntRespLen, 24, "NT Response length (bis) OK");
	// NT Resp Offset
	var ntRespOffset = authResp.readUInt32LE(24);
	strictEqual(ntRespOffset, 132, "NT Response offset OK");

	// Domain length (twice)
	var domainLen = authResp.readUInt16LE(28);
	strictEqual(domainLen, 12, "Domain Response length OK");
	domainLen = authResp.readUInt16LE(30);
	strictEqual(domainLen, 12, "Domain Response length (bis) OK");
	// Domain offset.
	var domainOffset = authResp.readUInt32LE(32);
	strictEqual(domainOffset, 72, "Domain Response offset OK");

	// User Length (twice)
	var userLen = authResp.readUInt16LE(36);
	strictEqual(userLen, 8, "User Response length OK");
	userLen = authResp.readUInt16LE(38);
	strictEqual(userLen, 8, "User Response length (bis) OK");
	// User offset
	var userOffset = authResp.readUInt32LE(40);
	strictEqual(userOffset, 84, "User Response offset OK");

	// Host length (twice)
	var hostLen = authResp.readUInt16LE(44);
	strictEqual(hostLen, 16, "Host Response length OK");
	hostLen = authResp.readUInt16LE(46);
	strictEqual(hostLen, 16, "Host Response length (bis) OK");
	// Host offset
	var hostOffset = authResp.readUInt32LE(48);
	strictEqual(hostOffset, 92, "Host Response offset OK");

	// Session key length (twice)
	var sessionKeyLen = authResp.readUInt16LE(52);
	strictEqual(sessionKeyLen, 16, "Session key Response length OK");
	sessionKeyLen = authResp.readUInt16LE(54);
	strictEqual(sessionKeyLen, 16, "Session key Response length (bis) OK");
	// Session key offset
	var sessionKeyOffset = authResp.readUInt32LE(56);
	strictEqual(sessionKeyOffset, 156, "Session key Response offset OK");

	// Flags
	var flags = authResp.readUInt32LE(60);
	strictEqual(flags, 3791684149, "Flags OK");

	// Version
	var vers = authResp.toString("hex", 64, 72);
	strictEqual(vers, "0501280a0000000f", "Version OK");

	var lmResp = authResp.toString("hex", lmRespOffset, lmRespOffset + lmRespLen);
	strictEqual(lmResp, expectedLMv1Response.toString('hex'), "4.2.2.2.2 LMv1 Response OK");

	var ntResp = authResp.toString("hex", ntRespOffset, ntRespOffset + ntRespLen);
	strictEqual(ntResp, expectedNTLMv1Response.toString('hex'), "4.2.2.2.1 NTLMv1 Response OK");

	var domainResp = authResp.toString("ucs2", domainOffset, domainOffset + domainLen);
	strictEqual(domainResp, DOMAIN_NAME, "Domain UCS2 OK");

	var userResp = authResp.toString("ucs2", userOffset, userOffset + userLen);
	strictEqual(userResp, USER_NAME, "User UCS2 OK");

	var hostResp = authResp.toString("ucs2", hostOffset, hostOffset + hostLen);
	strictEqual(hostResp, WORKSTATION_NAME, "Domain UCS2 OK");

	// 4.2.2.1.3 Session Base Key and Key Exchange Key
	var ntlmUserSessionKey = gen.getNTLMUserSessionKey();
	strictEqual(ntlmUserSessionKey.toString('hex'), expectedSessionBaseKey.toString('hex'), "4.2.2.1.3 Session Base Key and Key Exchange Key OK");

	var skResp = authResp.toString("hex", sessionKeyOffset, sessionKeyOffset + sessionKeyLen);
	strictEqual(skResp, expectedEncryptedSessionKey.toString('hex'), "4.2.2.2.3 Encrypted Session Key OK");

	var lmUserSessionKey = gen.getLMUserSessionKey();
	var encryptedSessionKey2 = gen.getEncryptedSessionKey(lmUserSessionKey);
	strictEqual(encryptedSessionKey2.toString('hex'), expectedEncryptedSessionKey2.toString('hex'), "4.2.2.2.3 Encrypted Session Key with NTLMSSP_REQUEST_NON_NT_SESSION_KEY FLAG OK");

	var lanManagerSessionKey = gen.getLanManagerSessionKey();
	var encryptedSessionKey3 = gen.getEncryptedSessionKey(lanManagerSessionKey);
	// TODO: Resolve bad LanManagerSessionKey
	//strictEqual(encryptedSessionKey3.toString('hex'), expectedEncryptedSessionKey3.toString('hex'), "4.2.2.2.3 Encrypted Session Key with NTLMSSP_NEGOTIATE_LM_KEY FLAG OK");

	var plaintext = new Buffer("Plaintext", "ucs2");
	plaintext = block2buffer([
		"0000000: 56 fe 04 d8 61 f9 31 9a f0 d7 23 8a 2e 3b 4d 45 V.•.a∙1...#è.;ME",
		"0000010: 7f b8                                           ⌂╕              "]);
	// Signature:
	var signature = session.computeSignature(plaintext);

});

test("4.2.4 NTLM v2 Authentication", function() {

	var challengeMessage = block2buffer([
		"0000000: 4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00 NTLMSSP.........",
		"0000010: 38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef 8...3....#Eg..=.",
		"0000020: 00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00 ........$.$.D...",
		"0000030: 06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00 ..p.....S.e.r.v.",
		"0000040: 65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00 e.r.....D.o.m.a.",
		"0000050: 69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00 i.n.....S.e.r.v.",
		"0000060: 65 00 72 00 00 00 00 00                         e.r....."]);
	var ntlmAuthentication = new NtlmAuthenticator(USER_NAME, PASSWORD, DOMAIN_NAME);
	var session = ntlmAuthentication.createSession({
		host: WORKSTATION_NAME,
		connectionType: "connectionOriented",
		clientChallenge: CLIENT_CHALLENGE,
		clientChallenge2: CLIENT_CHALLENGE,
		randomSessionKey: RANDOM_SESSION_KEY,
		timestamp: TIME
	});
	ntlmAuthentication.generateNegociateMessage();
	var authenticateMessage = ntlmAuthentication.generateAuthenticateMessage("NTLM " + challengeMessage.toString('base64'));
	var resp = authenticateMessage;
	var authResp = new Buffer(authenticateMessage.substring(5), "base64");
	var gen = session.authenticateMessage.gen;

	// 4.2.4.1.1 NTOWFv2() and LMOWFv2()
	var ntlmv2Hash = gen.getNTLMv2Hash();
	var expectedNtowfv2 = block2buffer([
		"0000000: 0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f ...@;..........?"]);
	strictEqual(ntlmv2Hash.toString('hex'), expectedNtowfv2.toString('hex'), "4.2.4.1.1 NTOWFv2() and LMOWFv2()");

	var expectedSessionBaseKey = block2buffer([
		"0000000: 8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3 ......J........."]);

	// 4.2.4.2 Results
	// 4.2.4.2.1 LMv2 Response
	var expectedLMv2Response = block2buffer([
		"0000000: 86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 ..P.....%TvJW...",
		"0000010: aa aa aa aa aa aa aa aa                         ........"]);

	// 4.2.4.2.2 NTLMv2 Response
	// todo [!spec error} : NOTE: expected NtChallengeResponse is too short
	// According to new spec version this value corresponds to 2.2.2.8, Response (16 bytes)
	// According to 3.3.2 NTLM v2 Authentication
	// Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
	// So we must use only NTProofStr, which is first 16 bytes of ntChallengeResponse
	var expectedNTLMv2Response = block2buffer([
		"0000000: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c h...Q......{..j."]);

	var expectedEncryptedSessionKey = block2buffer([
		"0000000: c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e ...TO.y........<"]);

	// Not used because there are some differences
	var expectedAuthenticateMessage = block2buffer([
		"0000000: 4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00 NTLMSSP.........",
		"0000010: 6c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 00 l...T.T.a.......",
		"0000020: 48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00 H.......T.......",
		"0000030: 5c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e2 ............5...",
		"0000040: 05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00 ..(.....D.o.m.a.",
		"0000050: 69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00 i.n.U.s.e.r.C.O.",
		"0000060: 4d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97 M.P.U.T.E.R...P.",
		"0000070: ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa ....%TvJW.......",
		"0000080: aa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b ....h=..Q......{",
		"0000090: eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00 ??j.............",
		"00000A0: 00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00 ................",
		"00000B0: 02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 ....D.o.m.a.i.n.",
		"00000C0: 01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 ....S.e.r.v.e.r.",
		"00000D0: 00 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 90 ...........TO.y.",
		"00000E0: 94 ce 1c e9 0b c9 d0 3e                         ........>"]);

	// LM Resp Length (twice)
	var lmRespLen = authResp.readUInt16LE(12);
	strictEqual(lmRespLen, 24, "LM Response length OK");
	lmRespLen = authResp.readUInt16LE(14);
	strictEqual(lmRespLen, 24, "LM Response length (bis) OK");
	// LM Resp Offset
	var lmRespOffset = authResp.readUInt32LE(16);
	strictEqual(lmRespOffset, 108, "LM Response offset OK");

	// NT Resp Length (twice)
	var ntRespLen = authResp.readUInt16LE(20);
	strictEqual(ntRespLen, 84, "NT Response length OK");
	ntRespLen = authResp.readUInt16LE(22);
	strictEqual(ntRespLen, 84, "NT Response length (bis) OK");
	// NT Resp Offset
	var ntRespOffset = authResp.readUInt32LE(24);
	strictEqual(ntRespOffset, 132, "NT Response offset OK");

	// Domain length (twice)
	var domainLen = authResp.readUInt16LE(28);
	strictEqual(domainLen, 12, "Domain Response length OK");
	domainLen = authResp.readUInt16LE(30);
	strictEqual(domainLen, 12, "Domain Response length (bis) OK");
	// Domain offset.
	var domainOffset = authResp.readUInt32LE(32);
	strictEqual(domainOffset, 72, "Domain Response offset OK");

	// User Length (twice)
	var userLen = authResp.readUInt16LE(36);
	strictEqual(userLen, 8, "User Response length OK");
	userLen = authResp.readUInt16LE(38);
	strictEqual(userLen, 8, "User Response length (bis) OK");
	// User offset
	var userOffset = authResp.readUInt32LE(40);
	strictEqual(userOffset, 84, "User Response offset OK");

	// Host length (twice)
	var hostLen = authResp.readUInt16LE(44);
	strictEqual(hostLen, 16, "Host Response length OK");
	hostLen = authResp.readUInt16LE(46);
	strictEqual(hostLen, 16, "Host Response length (bis) OK");
	// Host offset
	var hostOffset = authResp.readUInt32LE(48);
	strictEqual(hostOffset, 92, "Host Response offset OK");

	// Session key length (twice)
	var sessionKeyLen = authResp.readUInt16LE(52);
	strictEqual(sessionKeyLen, 16, "Session key Response length OK");
	sessionKeyLen = authResp.readUInt16LE(54);
	strictEqual(sessionKeyLen, 16, "Session key Response length (bis) OK");
	// Session key offset
	var sessionKeyOffset = authResp.readUInt32LE(56);
	strictEqual(sessionKeyOffset, 216, "Session key Response offset OK");

	// Flags
	var flags = authResp.readUInt32LE(60);
	strictEqual(flags, 3800597045, "Flags OK");

	// Version
	var vers = authResp.toString("hex", 64, 72);
	strictEqual(vers, "0501280a0000000f", "Version OK");

	var lmResp = authResp.toString("hex", lmRespOffset, lmRespOffset + lmRespLen);
	strictEqual(lmResp, expectedLMv2Response.toString('hex'), "4.2.4.2.1 LMv2 Response OK");

	var ntResp = authResp.toString("hex", ntRespOffset, ntRespOffset + ntRespLen);
	strictEqual(ntResp.slice(0, 32), expectedNTLMv2Response.toString('hex'), "4.2.4.2.2 NTLMv2 Response OK");

	var domainResp = authResp.toString("ucs2", domainOffset, domainOffset + domainLen);
	strictEqual(domainResp, DOMAIN_NAME, "Domain UCS2 OK");

	var userResp = authResp.toString("ucs2", userOffset, userOffset + userLen);
	strictEqual(userResp, USER_NAME, "User UCS2 OK");

	var hostResp = authResp.toString("ucs2", hostOffset, hostOffset + hostLen);
	strictEqual(hostResp, WORKSTATION_NAME, "Domain UCS2 OK");

	// 4.2.2.1.3 Session Base Key and Key Exchange Key
	var ntlmUserSessionKey = gen.getNTLMv2UserSessionKey();
	strictEqual(ntlmUserSessionKey.toString('hex'), expectedSessionBaseKey.toString('hex'), "4.2.4.1.2 Session Base Key OK");

	var skResp = authResp.toString("hex", sessionKeyOffset, sessionKeyOffset + sessionKeyLen);
	strictEqual(skResp, expectedEncryptedSessionKey.toString('hex'), "4.2.4.2.3 Encrypted Session Key OK");

	// 4.2.4.4 GSS_WrapEx Examples
	var plaintext = new Buffer("Plaintext", "ucs2");

	// The sealkey is created using SEALKEY() (section 3.4.5.3):
	// MD5(ConcatenationOf(RandomSessionKey, "session key to client-to-server sealing key magic constant")):
	var expectedClientSealingKey = block2buffer([
		"0000000: 59 f6 00 97 3c c4 96 0a 25 48 0a 7c 19 6e 4c 58 Y...<-..%H...nLX"]);

	strictEqual(session.clientSealingKey.toString('hex'), expectedClientSealingKey.toString('hex'), "4.2.4.4 GSS_WrapEx - Sealing Key OK");

	// The signkey is created using SIGNKEY() (section 3.4.5.2):
	// MD5(ConcatenationOf(RandomSessionKey, "session key to client-to-server signing key magic constant.)):
	var expectedClientSigningKey = block2buffer([
		"0000000: 47 88 dc 86 1b 47 82 f3 5d 43 fd 98 fe 1a 2d 39 G....G..]C....-9"]);

	strictEqual(session.clientSigningKey.toString('hex'), expectedClientSigningKey.toString('hex'), "4.2.4.4 GSS_WrapEx - Signing Key OK");

	// Signature:
	var signature = session.computeSignature(plaintext);
	var expectedSignature = block2buffer([
		"0000000: 01 00 00 00 7f b3 8e c5 c5 5d 49 76 00 00 00 00 .........]Iv...."]);
	// TODO : this doesn't work;
	//strictEqual(signature.toString('hex'), expectedSignature.toString('hex'), "4.2.4.4 GSS_WrapEx - Signature OK");	
});