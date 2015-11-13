"use strict";

const crypto = require('crypto');

/*
[MS-NLMP]
2.2.2.5 NEGOTIATE
During NTLM authentication, each of the following flags is a possible value of the NegotiateFlags
field of the NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE, unless
otherwise noted. These flags define client or server NTLM capabilities supported by the sender.
*/
const NTLMSSP_NEGOTIATE_UNICODE_FLAG = 0x00000001; /* A  */
const NTLMSSP_NEGOTIATE_OEM_FLAG = 0x00000002; /* B  */
const NTLMSSP_REQUEST_TARGET_FLAG = 0x00000004; /* C  */
//const r9						0x00000008	/* r9 */
const NTLMSSP_NEGOTIATE_SIGN_FLAG = 0x00000010; /* D  */
const NTLMSSP_NEGOTIATE_SEAL_FLAG = 0x00000020; /* E  */
const NTLMSSP_NEGOTIATE_DATAGRAM_FLAG = 0x00000040; /* F  */
const NTLMSSP_NEGOTIATE_LM_KEY_FLAG = 0x00000080; /* G  */
//const r8						0x00000100	/* r8 */
const NTLMSSP_NEGOTIATE_NTLM_FLAG = 0x00000200; /* H  */
const NTLMSSP_NEGOTIATE_NT_ONLY_FLAG = 0x00000400; /* I  */
const NTLMSSP_NEGOTIATE_anonymous_FLAG = 0x00000800; /* J  */
const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED_FLAG = 0x00001000; /* K  */
const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED_FLAG = 0x00002000; /* L  */
//const r7						0x00004000	/* r7 */
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG = 0x00008000; /* M  */
const NTLMSSP_TARGET_TYPE_DOMAIN_FLAG = 0x00010000; /* N  */
const NTLMSSP_TARGET_TYPE_SERVER_FLAG = 0x00020000; /* O  */
//const r6						0x00040000	/* r6 */
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG = 0x00080000; /* P  */
const NTLMSSP_NEGOTIATE_IDENTIFY_FLAG = 0x00100000; /* Q  */
//const r5						0x00200000	/* r5 */
const NTLMSSP_REQUEST_NON_NT_SESSION_KEY_FLAG = 0x00400000; /* R  */
const NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG = 0x00800000; /* S  */
//const r4						0x01000000	/* r4 */
const NTLMSSP_NEGOTIATE_VERSION_FLAG = 0x02000000; /* T  */
//const r3						0x04000000	/* r3 */
//const r2						0x08000000	/* r2 */
//const r1						0x10000000	/* r1 */
const NTLMSSP_NEGOTIATE_128_FLAG = 0x20000000; /* U  */
const NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG = 0x40000000; /* V  */
const NTLMSSP_NEGOTIATE_56_FLAG = 0x80000000; /* W  */

/* Minimum set of common features we need to work. */
/* we operate in NTLMv2 mode */
const NEGOTIATE_FLAGS_COMMON_MIN = bitWiseOr([
NTLMSSP_NEGOTIATE_UNICODE_FLAG,
NTLMSSP_NEGOTIATE_NTLM_FLAG,
NTLMSSP_NEGOTIATE_ALWAYS_SIGN_FLAG,
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG,
NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG]);

/* Negotiate flags for connection-based mode. Nice to have but optional. */
const NEGOTIATE_FLAGS_CONN = bitWiseOr([
NEGOTIATE_FLAGS_COMMON_MIN,
NTLMSSP_NEGOTIATE_VERSION_FLAG,
NTLMSSP_NEGOTIATE_128_FLAG,
NTLMSSP_NEGOTIATE_56_FLAG,
NTLMSSP_REQUEST_TARGET_FLAG]);

/* Extra negotiate flags required in connectionless NTLM */
const NEGOTIATE_FLAGS_CONNLESS_EXTRA = bitWiseOr([
NTLMSSP_NEGOTIATE_SIGN_FLAG,
NTLMSSP_NEGOTIATE_DATAGRAM_FLAG,
NTLMSSP_NEGOTIATE_IDENTIFY_FLAG,
NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG]);

/* Negotiate flags required in connectionless NTLM */
const NEGOTIATE_FLAGS_CONNLESS = bitWiseOr([NEGOTIATE_FLAGS_CONN, NEGOTIATE_FLAGS_CONNLESS_EXTRA]);

const magicString = {
	client: {
		signing: "session key to client-to-server signing key magic constant",
		sealing: "session key to client-to-server sealing key magic constant"
	},
	server: {
		signing: "session key to server-to-client signing key magic constant",
		sealing: "session key to server-to-client sealing key magic constant"
	}
};

const windowsVersions = [
	"0501280A0000000F", // WindowsXp
"060072170000000F", // WindowsVista
"0601B11D0000000F" // Windows7
];

/** Strip dot suffix from a name */
function stripDotSuffix(value) {
	const index = value.indexOf(".");
	if (index !== -1) return value.substring(0, index);
	return value;
}

/** Convert host to standard form */
function convertHost(host) {
	return stripDotSuffix(host);
}

/** Convert domain to standard form */
function convertDomain(domain) {
	return stripDotSuffix(domain);
}

const PARITY = [];

for (var i = 0; i < 256; i++) {
	var sum = 0;
	for (var j = 0; j < 8; j++) sum += (i >> j) & 1;
	PARITY[i] = sum % 2 ? i : i ^ 1;
}

/**
 * Calculates the NTLM2 Session Response for the given challenge, using the
 * specified password and client challenge.
 *
 * @return The NTLM2 Session Response. This is placed in the NTLM response
 *         field of the Type 3 message; the LM response field contains the
 *         client challenge, null-padded to 24 bytes.
 */
const ntlm2SessionResponse = function(_ntlmHash, challenge, clientChallenge) {
	try {
		const digest = crypto.createHash('md5').update(challenge).update(clientChallenge).digest();
		return lmResponse(_ntlmHash, digest.slice(0, 8));
	} catch (e) {
		throw new Error(e.message, e);
	}
};

/**
 * Creates the LM Hash of the user's password.
 * This is a 32-bit hexadecimal sequence that represents the password clients will use.
 * It is derived by encrypting the string  KGS!@#$% with a 56-bit DES algorithm using
 * the user's password (forced to 14 bytes and converted to capital letters) twice
 * repeated as the key.
 * 
 * @param password The password.
 *
 * @return The LM Hash (in hexadecimal) of the given password, used in the calculation
 * of the LM Response.
 */
const lmHash = function(password) {
	const magic = 'KGS!@#$%';
	const lm_pw = new Buffer(14);
	for (var i = 0; i < 14; i++) {
		lm_pw[i] = password[i] ? password.toUpperCase().charCodeAt(i) : 0x00;
	}
	var lm_hpw = des_encrypt(lm_pw.slice(0, 7), magic, 'ascii');
	lm_hpw += des_encrypt(lm_pw.slice(7), magic, 'ascii');
	return lm_hpw;
};

/**
 * Creates the NTLM Hash of the user's password.
 * This is a 32-bit hexadecimal sequence that represents the password Windows NT clients
 * will use. It is derived by hashing the user's password (represented as a 16-bit little-endian
 * Unicode sequence) with an MD4 hash. The password is not converted to uppercase letters first.
 * 
 * @param password The password.
 * 
 * @return The NTLM Hash (in hexadecimal) of the given password, used in the calculation
 * of the NTLM Response and the NTLMv2 and LMv2 Hashes.
 */
const ntlmHash = function(password) {
	return crypto.createHash('md4').update(new Buffer(password, 'ucs2')).digest('hex');
};

/**
 * Creates the NTLMv2 Hash of the user's password.
 * 
 * @param target The authentication target (i.e., domain).
 * @param user The username.
 * @param password The password.
 * 
 * @return The NTLMv2 Hash, used in the calculation of the NTLMv2
 * and LMv2 Responses. 
 */
const ntlmv2Hash = function(target, user, _ntlmHash) {
	const identity = user.toUpperCase() + target;
	return crypto.createHmac('md5', _ntlmHash).update(new Buffer(identity, 'ucs2')).digest('hex');
};

const lmv2Hash = function(target, user, _ntlmHash) {
	const identity = Buffer.concat([new Buffer(user.toUpperCase(), 'ucs2'), new Buffer(target.toUpperCase(), 'ucs2')]);
	return crypto.createHmac('md5', _ntlmHash).update(identity).digest('hex');
};

/**
 * Creates the LM Response from the given hash and Type 2 challenge.
 *
 * @param hash The LM or NTLM Hash.
 * @param challenge The server challenge from the Type 2 message.
 *
 * @return The response (either LM or NTLM, depending on the provided
 * hash).
 */
const lmResponse = function(hash, challenge) {
	function padHash(buf) {
		const newBuf = new Buffer(21);
		buf.copy(newBuf);
		for (var i = 16; i < 21; i++) {
			newBuf[i] = 0x00;
		}
		return newBuf;
	}

	const keys = padHash(hash);
	var resp = des_encrypt(keys.slice(0, 7), challenge, 'ascii');
	resp += des_encrypt(keys.slice(7, 14), challenge, 'ascii');
	resp += des_encrypt(keys.slice(14), challenge, 'ascii');

	return new Buffer(resp, 'hex');
};

/**
 * Creates the LMv2 Response from the given hash, client data, and
 * Type 2 challenge.
 *
 * @param hash The NTLMv2 Hash.
 * @param clientData The client data (blob or client challenge).
 * @param challenge The server challenge from the Type 2 message.
 *
 * @return The response (either NTLMv2 or LMv2, depending on the
 * client data).
 */
const lmv2Response = function(hash, challenge, clientData) {
	const data = Buffer.concat([challenge, clientData], challenge.length + clientData.length);
	const macHex = crypto.createHmac('md5', hash).update(data).digest('hex');
	const mac = new Buffer(macHex, 'hex');
	return Buffer.concat([mac, clientData], mac.length + clientData.length);
};

/**
 * Creates the NTLMv2 blob from the given target information block and
 * client challenge.
 *
 * @param clientNonce The random 8-byte client challenge.
 * @param targetInformation The target information block from the Type 2
 * message.
 * @param timestamp The timestamp information to send
 *
 * @return Buffer The blob, used in the calculation of the NTLMv2 Response.
 */
const createBlob = function(clientNonce, targetInformation, timestamp) {
	const blobSignature = new Buffer([0x01, 0x01, 0x00, 0x00]);
	const reserved = new Buffer([0x00, 0x00, 0x00, 0x00]);
	const unknown1 = new Buffer([0x00, 0x00, 0x00, 0x00]);
	const unknown2 = new Buffer([0x00, 0x00, 0x00, 0x00]);
	const blobLen = blobSignature.length + reserved.length + timestamp.length + clientNonce.length + unknown1.length + targetInformation.length + unknown2.length;
	return Buffer.concat([blobSignature, reserved, timestamp, clientNonce, unknown1, targetInformation, unknown2], blobLen);
};

/**
 * Creates a DES encryption key from the given key material.
 *
 * @param str Data to encrypt.
 * @param key The key to use for the encryption.
 *
 * @return Encrypted data.
 */
const des_encrypt = function(ks, str, encoding) {
	/**
	 * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
	 * The key schedule ks is also set.
	 */
	const setup_des_key = function(key_56) {
		function odd_parity(key) {
			for (var i = 0; i < 8; i++) {
				key[i] = PARITY[key[i]];
			}
		}
		const key = new Buffer(8);
		key[0] = key_56[0];
		key[1] = ((key_56[0] << 7) & 0xff) | (key_56[1] >> 1);
		key[2] = ((key_56[1] << 6) & 0xff) | (key_56[2] >> 2);
		key[3] = ((key_56[2] << 5) & 0xff) | (key_56[3] >> 3);
		key[4] = ((key_56[3] << 4) & 0xff) | (key_56[4] >> 4);
		key[5] = ((key_56[4] << 3) & 0xff) | (key_56[5] >> 5);
		key[6] = ((key_56[5] << 2) & 0xff) | (key_56[6] >> 6);
		key[7] = (key_56[6] << 1) & 0xff;
		odd_parity(key);
		return key;
	};

	ks = setup_des_key(ks);
	const iv = new Buffer(8);
	for (var i = 0; i < 8; i++) iv[i] = 0x00;
	const tokencrypt = crypto.createCipheriv('des-cbc', ks, iv);
	const token = tokencrypt.update(str, encoding, 'hex');
	tokencrypt.final('hex');
	return token;
};

/**
 * RC4 encryption
 */
const rc4_encrypt = function(buf, key) {

	const S = new Buffer(256);
	const T = new Buffer(256);

	var keylen, i, j;
	if (key.length < 1 || key.length > 256) {
		throw new Error("RC4 key must be between 1 and 256 bytes");
	} else {
		keylen = key.length;
		for (i = 0; i < 256; i++) {
			S[i] = i & 0xff;
			T[i] = key[i % keylen];
		}
		j = 0;
		for (i = 0; i < 256; i++) {
			j = (j + S[i] + T[i]) & 0xFF;
			S[i] ^= S[j];
			S[j] ^= S[i];
			S[i] ^= S[j];
		}
	}

	i = 0;
	j = 0;
	const ciphertext = new Buffer(buf.length);
	var counter, k, t;
	for (counter = 0; counter < buf.length; counter++) {
		i = (i + 1) & 0xFF;
		j = (j + S[i]) & 0xFF;
		S[i] ^= S[j];
		S[j] ^= S[i];
		S[i] ^= S[j];
		t = (S[i] + S[j]) & 0xFF;
		k = S[t];
		ciphertext[counter] = (buf[counter] ^ k) & 0xFF;
	}
	return ciphertext;
};

/**
 * Calculates the CRC32 checksum of a string.
 *
 * @param {String} str
 * @param {Boolean} hex
 * @return {String} checksum
 * @api public
 */
const crc32Checksum = function(str, hex) {
	const crc32tab = [
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d];

	var crc = ~0,
		i, l;
	for (i = 0, l = str.length; i < l; i++) {
		crc = (crc >>> 8) ^ crc32tab[(crc ^ str.charCodeAt(i)) & 0xff];
	}
	crc = Math.abs(crc ^ -1);
	return hex ? crc.toString(16) : crc;
};

/**
 * Bitwise operations on 32-bit unsigned ints?
 */
function bitWiseOr(arr) {
	var result = arr[0];
	for (var i = 1; i < arr.length; i++) {
		result = (result | arr[i]) >>> 0;
	}
	return result;
}

const CipherGen = exports.CipherGen = class CipherGen {
	constructor(domain, user, password, challenge, target, targetInformation, clientChallenge, clientChallenge2, randomSessionKey, timestamp) {
		this.domain = domain;
		this.target = target;
		this.user = user;
		this.password = password;
		this.challenge = challenge;
		this.targetInformation = targetInformation;
		this.clientChallenge = clientChallenge;
		this.clientChallenge2 = clientChallenge2;
		this.randomSessionKey = randomSessionKey;
		this.timestamp = timestamp;

		// Stuff we always generate
		this.lmHash = null;
		this.lmResponse = null;
		this.ntlmHash = null;
		this.ntlmResponse = null;
		this.ntlmv2Hash = null;
		this.lmv2Hash = null;
		this.lmv2Response = null;
		this.ntlmv2Blob = null;
		this.ntlmv2Response = null;
		this.ntlm2SessionResponse = null;
		this.lm2SessionResponse = null;
		this.lmUserSessionKey = null;
		this.ntlmUserSessionKey = null;
		this.ntlmv2UserSessionKey = null;
		this.ntlm2SessionResponseUserSessionKey = null;
		this.lanManagerSessionKey = null;

		this.MAC_VERSION = new Buffer([1, 0, 0, 0]);
	}

	/** Calculate and return client challenge */
	getClientChallenge() {
		if (this.clientChallenge == null) this.clientChallenge = crypto.randomBytes(8);
		return this.clientChallenge;
	}

	/** Calculate and return second client challenge */
	getClientChallenge2() {
		if (this.clientChallenge2 == null) this.clientChallenge2 = crypto.randomBytes(8);
		return this.clientChallenge2;
	}

	/** Calculate and return random secondary key */
	getRandomSessionKey() {
		if (this.randomSessionKey == null) this.randomSessionKey = crypto.randomBytes(16);
		return this.randomSessionKey;
	}

	/** Calculate and return the LMHash */
	getLMHash() {
		if (this.lmHash == null) this.lmHash = new Buffer(lmHash(this.password), 'hex');
		return this.lmHash;
	}

	/** Calculate and return the LMResponse */
	getLMResponse() {
		if (this.lmResponse == null) this.lmResponse = lmResponse(this.getLMHash(), this.challenge);
		return this.lmResponse;
	}

	/** Calculate and return the NTLMHash */
	getNTLMHash() {
		if (this.ntlmHash == null) this.ntlmHash = new Buffer(ntlmHash(this.password), 'hex');
		return this.ntlmHash;
	}

	/** Calculate and return the NTLMResponse */
	getNTLMResponse() {
		if (this.ntlmResponse == null) this.ntlmResponse = lmResponse(this.getNTLMHash(), this.challenge);
		return this.ntlmResponse;
	}

	/** Calculate the LMv2 hash */
	getLMv2Hash() {
		if (this.lmv2Hash == null) this.lmv2Hash = new Buffer(lmv2Hash(this.domain, this.user, this.getNTLMHash()), 'hex');
		return this.lmv2Hash;
	}

	/** Calculate the NTLMv2 hash */
	getNTLMv2Hash() {
		if (this.ntlmv2Hash == null) this.ntlmv2Hash = new Buffer(ntlmv2Hash(this.domain, this.user, this.getNTLMHash()), 'hex');
		return this.ntlmv2Hash;
	}

	/** Calculate a timestamp */
	getTimestamp(millis) {
		millis = new Date().getTime();
		// shift origin to Jan 1, 1601
		var t = millis + 11644473600000;
		// t uses 44 bits. JS integers only have 52 bits.
		// We can't multiply by 10000 because result would need 57 bits
		// So we divide by 16 to gain 4 bits and we multiply by 625
		// instead of 10000 to save another 4 bits  (625 == 10000 / 16).
		// Caution: don't divide with >> 4 at it treats operands as 32 bit integers.
		t = Math.floor(t / 16) * 625;
		// t is the value to serialize, divided by 256.
		const buf = new Buffer(8);
		buf[0] = 0; // set lower bits to 0 to cope for 256 division
		for (var i = 1; i < 8; i++) {
			buf[i] = t & 0xff;
			t = Math.floor(t / 256);
		}
		return buf;
	}

	/** Calculate the NTLMv2Blob */
	getNTLMv2Blob() {
		if (this.ntlmv2Blob == null) this.ntlmv2Blob = createBlob(this.getClientChallenge2(), this.targetInformation, this.timestamp || this.getTimestamp());
		return this.ntlmv2Blob;
	}

	/** Calculate the NTLMv2Response */
	getNTLMv2Response() {
		if (this.ntlmv2Response == null) this.ntlmv2Response = lmv2Response(this.getNTLMv2Hash(), this.challenge, this.getNTLMv2Blob());
		return this.ntlmv2Response;
	}

	/** Calculate the LMv2Response */
	getLMv2Response() {
		if (this.lmv2Response == null) this.lmv2Response = lmv2Response(this.getNTLMv2Hash(), this.challenge, this.getClientChallenge());
		return this.lmv2Response;
	}

	/** Get NTLM2SessionResponse */
	getNTLM2SessionResponse() {
		if (this.ntlm2SessionResponse == null) this.ntlm2SessionResponse = ntlm2SessionResponse(this.getNTLMHash(), this.challenge, this.getClientChallenge());
		return this.ntlm2SessionResponse;
	}

	/** Calculate and return LM2 session response */
	getLM2SessionResponse() {
		if (this.lm2SessionResponse == null) {
			const _clientChallenge = this.getClientChallenge();
			this.lm2SessionResponse = Buffer.concat([_clientChallenge.slice(0, _clientChallenge.length), new Buffer([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]);
		}
		return this.lm2SessionResponse;
	}

	/** Get LMUserSessionKey */
	getLMUserSessionKey() {
		if (this.lmUserSessionKey == null) {
			const _lmHash = this.getLMHash();
			this.lmUserSessionKey = Buffer.concat([_lmHash.slice(0, 8), new Buffer([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]);
		}
		return this.lmUserSessionKey;
	}

	/** Get NTLMUserSessionKey */
	getNTLMUserSessionKey() {
		if (this.ntlmUserSessionKey == null) {
			const _ntlmHash = this.getNTLMHash();
			this.ntlmUserSessionKey = new Buffer(crypto.createHash('md4').update(_ntlmHash).digest('hex'), 'hex');
		}
		return this.ntlmUserSessionKey;
	}

	/** GetNTLMv2UserSessionKey */
	getNTLMv2UserSessionKey() {
		if (this.ntlmv2UserSessionKey == null) {
			const _ntlmv2hash = this.getNTLMv2Hash();
			const truncatedResponse = this.getNTLMv2Response().slice(0, 16);
			this.ntlmv2UserSessionKey = new Buffer(crypto.createHmac('md5', _ntlmv2hash).update(truncatedResponse).digest('hex'), 'hex');
		}
		return this.ntlmv2UserSessionKey;
	}

	/** GetEncryptedSessionKey */
	getEncryptedSessionKey(sessionKey) {
		return rc4_encrypt(this.getRandomSessionKey(), sessionKey);
	}

	/** Get NTLM2SessionResponseUserSessionKey */
	getNTLM2SessionResponseUserSessionKey() {
		if (this.ntlm2SessionResponseUserSessionKey == null) {
			const ntlmUserSessionKey = this.getNTLMUserSessionKey();
			const ntlm2SessionResponseNonce = this.getLM2SessionResponse();
			const sessionNonce = Buffer.concat([this.challenge, ntlm2SessionResponseNonce]);
			this.ntlm2SessionResponseUserSessionKey = new Buffer(crypto.createHmac('md5', ntlmUserSessionKey).update(sessionNonce).digest('hex'), 'hex');
		}
		return this.ntlm2SessionResponseUserSessionKey;
	}

	/** Get LAN Manager session key */
	getLanManagerSessionKey() {
		if (this.lanManagerSessionKey == null) {
			const lmHash = this.getLMHash();
			const lmResponse = this.getLMResponse();
			//
			//			const keyBytes = new Buffer(14);
			//			for (var i = 0 ; i < 8 ; i++){
			//				keyBytes[i] = lmHash[i];
			//			}
			//			for (var j = 8 ; j < keyBytes.length ; j++){
			//				keyBytes[i] = 0xbd & 0xff;
			//			}
			//			const truncatedResponse = lmResponse.slice(0,8);
			//			const part1 = new Buffer(des_encrypt(keyBytes.slice(0,7), truncatedResponse, 'binary'), 'hex');
			//			const part2 = new Buffer(des_encrypt(keyBytes.slice(7), truncatedResponse, 'binary'), 'hex');
			//			this.lanManagerSessionKey = Buffer.concat([part1, part2]);
			//			

			const keyBytes = new Buffer(14);
			for (var i = 0; i < 8; i++) {
				keyBytes[i] = lmHash[i];
			}
			for (var j = 8; j < keyBytes.length; j++) {
				keyBytes[i] = 0xbd;
			}
			const truncatedResponse = lmResponse.slice(0, 8);

			this.lanManagerSessionKey = des_encrypt(keyBytes.slice(0, 7), truncatedResponse, "ascii");

			this.lanManagerSessionKey += des_encrypt(keyBytes.slice(7), truncatedResponse, "ascii");

		}
		return this.lanManagerSessionKey;
	}

	signkey(flags, keyType) {
		if ((flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG) !== 0) {
			const key = magicString[keyType].signing;
			const magicBuf = new Buffer(key.length + 1);
			magicBuf.write(key, 0, key.length, 'ascii');
			magicBuf.writeUInt8(0, key.length); // '\0'

			const data = Buffer.concat([this.getRandomSessionKey(), magicBuf]);
			const _signKey = crypto.createHash('md5').update(data).digest('hex');
			return new Buffer(_signKey, "hex");
		} else {
			return null;
		}
	}

	sealkey(flags, keyType) {
		var _sealKey;
		if ((flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG) !== 0) {
			if (flags & NTLMSSP_NEGOTIATE_128_FLAG !== 0) {
				_sealKey = this.getRandomSessionKey();
			} else if ((flags & NTLMSSP_NEGOTIATE_56_FLAG) !== 0) {
				_sealKey = this.getRandomSessionKey().slice(0, 7);
			} else {
				_sealKey = this.getRandomSessionKey().slice(0, 5);
			}
			const key = magicString[keyType].sealing;
			const magicBuf = new Buffer(key.length + 1);
			magicBuf.write(key, 0, key.length, 'ascii');
			magicBuf.writeUInt8(0, key.length); // '\0'

			const data = Buffer.concat([_sealKey, magicBuf]);
			_sealKey = new Buffer(crypto.createHash('md5').update(data).digest('hex'), "hex");
		} else {
			_sealKey = new Buffer(8);
			if ((flags & NTLMSSP_NEGOTIATE_56_FLAG) !== 0) {
				// todo [!] seems to be either spec error or examples error - see http://social.msdn.microsoft.com/Forums/en-US/os_windowsprotocols/thread/a6d0241f-b608-4863-bff0-7cb0bb4f27e2/
				/*
			                System.arraycopy(randomSessionKey, 0, _sealKey, 0, 7);
			                _sealKey[7] = (byte) 0xA0;
			*/
				_sealKey = this.getRandomSessionKey();
			} else {
				_sealKey = this.getRandomSessionKey().slice(0, 5);
				_sealKey[5] = 0xE5 & 0xff;
				_sealKey[6] = 0x38 & 0xff;
				_sealKey[7] = 0xB0 & 0xff;
			}
		}
		return _sealKey;
	}

	mac(negotiateFlags, seqNum, signingKey, sealingKey, randomPad, message, input_encoding) {
		if ((negotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG) !== 0) {
			/*
			3.4.4.2 With Extended Session Security
			When Extended Session Security (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) is
			negotiated and session security (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL) is
			negotiated, the message signature for NTLM with extended session security is a 16-byte value that
			contains the following components, as described by the NTLMSSP_MESSAGE_SIGNATURE structure:
			* A 4-byte version-number value that is set to 1.
			* The first eight bytes of the message's HMAC_MD5.
			* The 4-byte sequence number (SeqNum).
			If message integrity is negotiated, the message signature is calculated as follows:
			-- Input:
			--  SigningKey - The key used to sign the message.
			--  SealingKey - The key used to seal the message or checksum.
			--  Message - The message being sent between the client and server.
			--  SeqNum - Defined in section 3.1.1.
			--  Handle - The handle to a key state structure corresponding to the
			--          current state of the SealingKey
			--
			-- Output:
			--  An NTLMSSP_MESSAGE_SIGNATURE structure whose fields are defined
			    in section 2.2.2.9.
			--  SeqNum - Defined in section 3.1.1.
			--
			-- Functions used:
			--  ConcatenationOf() - Defined in Section 6.
			--  RC4() - Defined in Section 6.
			--  HMAC_MD5() - Defined in Section 6.
			*/
			const seqBuf = new Buffer(4);
			seqBuf.writeUInt32LE(seqNum, 0);

			const hmacMd5 = crypto.createHmac('md5', signingKey).update(seqBuf).update(message).digest('hex');
			const md5Result = new Buffer(hmacMd5, "hex").slice(0, 8);
			var checksum;
			if ((negotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG) !== 0) {
				try {
					// TODO : this doesn't work; also the signature too
					checksum = rc4_encrypt(md5Result.slice(0, 8), sealingKey);
				} catch (e) {
					throw new Error("Internal error");
				}
			} else {
				checksum = md5Result.slice(0, 8);
			}

			return Buffer.concat([this.MAC_VERSION, checksum, seqBuf]);

		} else {
			/*
			3.4.4.1 Without Extended Session Security
			When Extended Session Security (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) is not negotiated and session security (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL) is negotiated, the message signature for NTLM without extended session security is a 16-byte value that contains the following components, as described by the NTLMSSP_MESSAGE_SIGNATURE structure:
			* 4-byte version-number value that is set to 1.
			* 4-byte random pad.
			* The 4-bytes of the message's CRC32.
			* The 4-byte sequence number (SeqNum).
			If message integrity is negotiated, the message signature is calculated as follows:
			-- Input:
			-- SigningKey - The key used to sign the message.
			-- SealingKey - The key used to seal the message or checksum.
			-- RandomPad - A random number provided by the client. Typically 0.
			-- Message - The message being sent between the client and server.
			-- SeqNum - Defined in section 3.1.1.
			-- Handle - The handle to a key state structure corresponding to the
			-- current state of the SealingKey
			--
			-- Output:
			-- An NTLMSSP_MESSAGE_SIGNATURE structure whose fields are defined
			in section 2.2.2.9.
			-- SeqNum - Defined in section 3.1.1.
			--
			-- Functions used:
			-- ConcatenationOf() - Defined in Section 6.
			-- RC4() - Defined in Section 6.
			-- CRC32() - Defined in Section 6.
			*/

			const checkSum = crc32Checksum(message.toString('ucs2'), true);
			//console.log("CheckSum: "+checkSum);

			//			//macWithoutExtendedSessionSecurity(seqNum, randomPad, sealingKey, message);
			//			byte[] checksum = calculateCRC32(message);
			//			try {
			//			    /*byte[] randomPad = */sealingKey.doFinal(randomPadIn);
			//			    checksum = sealingKey.doFinal(checksum);
			//			    byte[] seqNum = sealingKey.doFinal(EMPTY_ARRAY);
			//			    byte[] seqNumInArray = intToBytes(seqNumIn);
			//			    for (int i = 0; i < seqNumInArray.length; i++) {
			//			        seqNum[i] = (byte) (seqNum[i] ^ seqNumInArray[i]);
			//			    }
			//			    return concat(MAC_VERSION, EMPTY_ARRAY, checksum, seqNum);
			//			} catch (Exception e) {
			//			    throw new RuntimeException("Internal error", e);
			//			}

		}
	}

}

class NTLMMessage {
	constructor(messageBody, expectedType) {
		if (messageBody != null && expectedType != null) {
			this.messageContents = new Buffer(messageBody, 'base64');
			if (this.messageContents.length < 13) throw new Error("NTLM message decoding error - packet too short");

			const valid = new Buffer("4e544c4d53535000", 'hex');
			for (var i = 0; i < 8; i++) {
				if (this.messageContents[i] !== valid[i]) throw new Error("NTLM message expected - instead got unrecognized bytes");
			}

			const type = this.messageContents.readUInt32LE(8, 12);
			if (type !== expectedType) throw new Error("NTLM type " + expectedType + " message expected - instead got type " + type);
		}
	}
	/** Read a security buffer from a position within the message buffer */
	readSecurityBuffer(index) {
		const length = this.messageContents.readUInt16LE(index);
		const offset = this.messageContents.readUInt32LE(index + 4);
		if (this.messageContents.length < offset + length) throw new Error("NTLM authentication - buffer too small for data item");
		return this.messageContents.slice(offset, offset + length);
	}

	parseAvFields(targetInfoBuf) {
		var id, fields = {}, j = 0;
		const AvId = [
			"MsvAvEOL", //0x0000: Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
		"MsvAvNbComputerName", //0x0001: The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
		"MsvAvNbDomainName", //0x0002: The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
		"MsvAvDnsComputerName", //0x0003: The fully qualified domain name (FQDN (1)) of the computer. The name MUST be in Unicode, and is not null-terminated.
		"MsvAvDnsDomainName", //0x0004: The FQDN (2) of the domain. The name MUST be in Unicode, and is not null-terminated.
		"MsvAvDnsTreeName", //0x0005: The FQDN (2) of the forest. The name MUST be in Unicode, and is not null-terminated.<11>
		"MsvAvFlags", //0x0006: A 32-bit value indicating server or client configuration.
		//0x00000001: indicates to the client that the account authentication is constrained.
		//0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.<12>
		//0x00000004: indicates that the client is providing a target SPN generated from an untrusted source.<13>
		"MsvAvTimestamp", //0x0007: A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<14>
		"MsvAvSingleHost", //0x0008: A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<15>
		"MsvAvTargetName", //0x0009: The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<16>
		"MsvChannelBindings" //0x000A: A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.<17>
		];
		while ((id = targetInfoBuf.readUInt16LE(j)) !== 0) {
			j += 2;
			const len = targetInfoBuf.readUInt16LE(j);
			j += 2;
			var value = targetInfoBuf.slice(j, j + len);
			if (id <= 5 || id === 9) {
				value = value.toString('ucs2');
			}
			fields[AvId[id]] = value;
			j += len;
		}
		return fields;
	}

	/**
	 * Prepares the object to create a response of the given length.
	 *
	 * @param maxlength
	 *            the maximum length of the response to prepare, not
	 *            including the type and the signature (which this method
	 *            adds).
	 */
	prepareResponse(maxlength, messageType) {
		this.messageContents = new Buffer(maxlength);
		// First 8 bytes: NTLMSSP[0]
		this.messageContents.write('NTLMSSP', 0, 7, 'ascii');
		this.messageContents.writeUInt8(0, 7); // '\0'
		// Next 4 bytes: Ulong
		this.messageContents.writeUInt32LE(messageType, 8);
	}

	/**
	 * Returns the response that has been generated after shrinking the
	 * array if required and base64 encodes the response.
	 *
	 * @return The response as above.
	 */
	getResponse() {
		this.response = this.messageContents.toString('base64');
		return this.response;
	}
}

exports.Type1Message = class Type1Message extends NTLMMessage {
	constructor(session, domain) {
		super();

		this.session = session;
		this.negotiateFlags = session.connectionType === "connectionOriented" ? NEGOTIATE_FLAGS_CONN : NEGOTIATE_FLAGS_CONNLESS;

		try {
			// Strip off domain name from the host!
			const unqualifiedHost = convertHost(session.host);
			// Use only the base domain name!
			const unqualifiedDomain = convertDomain(domain);

			this.hostBytes = new Buffer(unqualifiedHost, "ascii");
			this.domainBytes = new Buffer(unqualifiedDomain.toUpperCase(), "ascii");
		} catch (e) {
			throw new Error("Unicode unsupported: " + e.message, e);
		}

	}
	/**
	 * Getting the response involves building the message before returning
	 * it
	 */
	getResponse() {
		if (this.session.connectionType === "connectionOriented") {
			// Now, build the message. Calculate its length first, including
			// signature or type.
			const finalLength = 32 + 8 /*+ hostBytes.length + domainBytes.length */
			;

			// Set up the response. This will initialize the signature, message
			// type, and flags.
			this.prepareResponse(finalLength, 1);

			// Flags. These are the complete set of flags we support.
			this.messageContents.writeUInt32LE(this.negotiateFlags, 12, true);

			// Domain length (two times).
			this.messageContents.writeUInt16LE(this.domainBytes.length, 16);
			this.messageContents.writeUInt16LE(this.domainBytes.length, 18);
			// Domain offset.
			this.messageContents.writeUInt32LE(32 + this.hostBytes.length, 20);

			// Host length (two times).
			this.messageContents.writeUInt16LE(this.hostBytes.length, 24);
			this.messageContents.writeUInt16LE(this.hostBytes.length, 26);
			// Host offset (always 32 + 8).
			this.messageContents.writeUInt32LE(32 + 8, 28);

			// Version
			this.messageContents.writeUInt16LE(0x0105, 32);
			// Build
			this.messageContents.writeUInt32LE(2600, 34);
			// NTLM revision
			this.messageContents.writeUInt16LE(0x0f00, 38);
		} else {
			this.messageContents = new Buffer(0);
		}
		return NTLMMessage.prototype.getResponse.call(this);
	}
}

exports.Type2Message = class Type2Message extends NTLMMessage {
	constructor(message) {
		super(message, 2);

		// Type 2 message is laid out as follows:
		// First 8 bytes: NTLMSSP[0]
		// Next 4 bytes: Ulong, value 2
		// Next 8 bytes, starting at offset 12: target field (2 ushort lengths, 1 ulong offset)
		// Next 4 bytes, starting at offset 20: Flags, e.g. 0x22890235
		// Next 8 bytes, starting at offset 24: Challenge
		// Next 8 bytes, starting at offset 32: ??? (8 bytes of zeros)
		// Next 8 bytes, starting at offset 40: targetinfo field (2 ushort lengths, 1 ulong offset)
		// Next 2 bytes, major/minor version number (e.g. 0x05 0x02)
		// Next 8 bytes, build number
		// Next 2 bytes, protocol version number (e.g. 0x00 0x0f)
		// Next, various text fields, and a ushort of value 0 at the end

		// Parse out the rest of the info we need from the message
		// The challenge is the 8 bytes starting from the byte in position 24.
		this.challenge = this.messageContents.slice(24, 24 + 8);

		this.flags = this.messageContents.readUInt32LE(20);

		if ((this.flags & NTLMSSP_NEGOTIATE_UNICODE_FLAG) === 0) throw new Error("NTLM type 2 message has flags that make no sense: " + this.flags);

		// Do the target!
		this.target = null;
		// The TARGET_DESIRED flag is said to not have understood semantics
		// in Type2 messages, so use the length of the packet to decide
		// how to proceed instead
		if (this.messageContents.length >= 12 + 8) {
			const tnBuf = this.readSecurityBuffer(12);
			if (tnBuf.length !== 0) {
				try {
					this.target = tnBuf.toString('ucs2');
				} catch (e) {
					throw new Error(e.message, e);
				}
			}
		}

		// Do the target info!
		this.targetInfo = null;
		// TARGET_DESIRED flag cannot be relied on, so use packet length
		if (this.messageContents.length >= 40 + 8) {
			const tiBuf = this.readSecurityBuffer(40);
			if (tiBuf.length !== 0) {
				this.targetInfo = tiBuf;
			}
		}
	}
};

exports.Type3Message = class Type3Message extends NTLMMessage {
	constructor(session, user, password, domain) {
		super();
		this.session = session;

		// TODO: identify the real windows version
		// Set Windows Version to XP
		this.windowsVersion = windowsVersions[0];

		// Save the flags
		this.negotiateFlags = bitWiseOr([session.challengeMessage.flags, NTLMSSP_REQUEST_TARGET_FLAG]);
		if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_OEM_FLAG) !== 0) this.negotiateFlags -= NTLMSSP_TARGET_TYPE_SERVER_FLAG;

		if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_OEM_FLAG) !== 0 && (this.negotiateFlags & NTLMSSP_NEGOTIATE_UNICODE_FLAG) !== 0) {
			this.negotiateFlags -= NTLMSSP_NEGOTIATE_OEM_FLAG;
		}

		if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY_FLAG) !== 0 && (this.negotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG) !== 0) {
			this.negotiateFlags -= NTLMSSP_NEGOTIATE_LM_KEY_FLAG;
		}

		// Save Target information fields
		if (session.challengeMessage.targetInfo != null) {
			this.targetInfoFields = this.parseAvFields(session.challengeMessage.targetInfo);
			//console.log("Target info fields: "+JSON.stringify(this.targetInfoFields,null,2));
		}

		// Strip off domain name from the host!
		const unqualifiedHost = convertHost(session.host);
		// Use only the base domain name!
		const unqualifiedDomain = convertDomain(domain);

		try {
			this.domainBytes = new Buffer(unqualifiedDomain, 'ucs2');
			this.hostBytes = new Buffer(unqualifiedHost, 'ucs2');
			this.userBytes = new Buffer(user, 'ucs2');
		} catch (e) {
			throw new Error("Unicode not supported: " + e.message, e);
		}

		if (this.targetInfoFields && this.targetInfoFields.MsvAvTimestamp) {
			session.timestamp = this.targetInfoFields.MsvAvTimestamp;
		}
		if (this.targetInfoFields && this.targetInfoFields.MsvAvFlags) {
			// TODO: Set MsAvFlags in TargetInfo
		}

		// Create a cipher generator class.  Use domain BEFORE it gets modified!
		this.gen = new CipherGen(unqualifiedDomain, user, password, session.challengeMessage.challenge, session.challengeMessage.target, session.challengeMessage.targetInfo, session.clientChallenge, session.clientChallenge2, session.randomSessionKey, session.timestamp);

		try {
			// This conditional may not work on Windows Server 2008 R2 and above, where it has not yet
			// been tested
			if (((this.negotiateFlags & NTLMSSP_NEGOTIATE_TARGET_INFO_FLAG) !== 0) && session.challengeMessage.targetInfo != null && session.challengeMessage.target != null) {
				// NTLMv2
				this.ntResp = this.gen.getNTLMv2Response();
				this.lmResp = this.gen.getLMv2Response();
				if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY_FLAG) !== 0) {
					this.userSessionKey = this.gen.getLanManagerSessionKey();
				} else {
					this.userSessionKey = this.gen.getNTLMv2UserSessionKey();
				}
			} else {
				// NTLMv1
				if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY_FLAG) !== 0) {
					// NTLM2 session stuff is requested
					this.ntResp = this.gen.getNTLM2SessionResponse();
					this.lmResp = this.gen.getLM2SessionResponse();
					if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY_FLAG) !== 0) {
						this.userSessionKey = this.gen.getLanManagerSessionKey();
					} else {
						this.userSessionKey = this.gen.getNTLM2SessionResponseUserSessionKey();
					}
				} else {
					this.ntResp = this.gen.getNTLMResponse();
					this.lmResp = this.gen.getLMResponse();
					if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY_FLAG) !== 0) {
						this.userSessionKey = this.gen.getLanManagerSessionKey();
					} else if ((this.negotiateFlags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY_FLAG) !== 0) {
						this.userSessionKey = this.gen.getLMUserSessionKey();
					} else {
						this.userSessionKey = this.gen.getNTLMUserSessionKey();
					}
				}
			}
		} catch (e) {
			console.error(e.stack);
			// This likely means we couldn't find the MD4 hash algorithm -
			// fail back to just using LM
			this.ntResp = new Buffer(0);
			this.lmResp = this.gen.getLMResponse();
			if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_LM_KEY_FLAG) !== 0) {
				this.userSessionKey = this.gen.getLanManagerSessionKey();
			} else {
				this.userSessionKey = this.gen.getLMUserSessionKey();
			}
		}

		if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_SIGN_FLAG) !== 0) {
			if ((this.negotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH_FLAG) !== 0) {
				this.sessionKey = this.gen.getEncryptedSessionKey(this.userSessionKey);
			} else {
				this.sessionKey = this.userSessionKey || null;
			}
		} else {
			this.sessionKey = null;
		}
		this.calculateKeys();

	}

	calculateKeys() {
		this.session.clientSigningKey = this.gen.signkey(this.negotiateFlags, "client");
		this.session.serverSigningKey = this.gen.signkey(this.negotiateFlags, "server");
		this.session.clientSealingKey = this.gen.sealkey(this.negotiateFlags, "client");
		this.session.serverSealingKey = this.gen.sealkey(this.negotiateFlags, "server");
	}

	getResponse() {
		// Calculate the layout within the packet
		const domainOffset = 72; // TODO: allocate space (+16) for MIC
		const userOffset = domainOffset + this.domainBytes.length;
		const hostOffset = userOffset + this.userBytes.length;
		const lmRespOffset = hostOffset + this.hostBytes.length;
		const ntRespOffset = lmRespOffset + this.lmResp.length;
		const sessionKeyOffset = ntRespOffset + this.ntResp.length;
		const finalLength = sessionKeyOffset + (this.sessionKey != null ? this.sessionKey.length : 0);

		// Start the response. Length includes signature and type
		this.prepareResponse(finalLength, 3);

		/*
        2.2.1.3 AUTHENTICATE_MESSAGE
        */
		// LM Resp Length (twice)
		this.messageContents.writeUInt16LE(this.lmResp.length, 12);
		this.messageContents.writeUInt16LE(this.lmResp.length, 14);
		// LM Resp Offset
		this.messageContents.writeUInt32LE(lmRespOffset, 16);

		// NT Resp Length (twice)
		this.messageContents.writeUInt16LE(this.ntResp.length, 20);
		this.messageContents.writeUInt16LE(this.ntResp.length, 22);
		// NT Resp Offset
		this.messageContents.writeUInt32LE(ntRespOffset, 24);

		// Domain length (twice)
		this.messageContents.writeUInt16LE(this.domainBytes.length, 28);
		this.messageContents.writeUInt16LE(this.domainBytes.length, 30);
		// Domain offset.
		this.messageContents.writeUInt32LE(domainOffset, 32);

		// User Length (twice)
		this.messageContents.writeUInt16LE(this.userBytes.length, 36);
		this.messageContents.writeUInt16LE(this.userBytes.length, 38);
		// User offset
		this.messageContents.writeUInt32LE(userOffset, 40);

		// Host length (twice)
		this.messageContents.writeUInt16LE(this.hostBytes.length, 44);
		this.messageContents.writeUInt16LE(this.hostBytes.length, 46);
		// Host offset
		this.messageContents.writeUInt32LE(hostOffset, 48);

		// Session key length (twice)
		this.messageContents.writeUInt16LE(this.sessionKey != null ? this.sessionKey.length : 0, 52);
		this.messageContents.writeUInt16LE(this.sessionKey != null ? this.sessionKey.length : 0, 54);
		// Session key offset
		this.messageContents.writeUInt32LE(sessionKeyOffset, 56);

		// Flags
		this.messageContents.writeUInt32LE(this.negotiateFlags, 60);

		// TODO: Compute real version and MIC
		// Version
		/*
        A VERSION structure (section 2.2.2.10) that is present only when the
        NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field. This structure is used
        for debugging purposes only. In normal protocol messages, it is ignored and does not affect
        the NTLM message processing.<9>

         <9> Section 2.2.1.3: The Version field is NOT sent or consumed by Windows NT or Windows 2000.
        Windows NT and Windows 2000 assume that the Payload field started immediately after
        NegotiateFlags. Since all references into the Payload field are by offset from the start of the
        message (not from the start of the Payload field), Windows NT and Windows 2000 can correctly
        interpret messages constructed with Version fields
               
         */
		if (windowsVersions.indexOf(this.windowsVersion) >= windowsVersions.indexOf("0501280A0000000F") && (this.negotiateFlags & NTLMSSP_NEGOTIATE_VERSION_FLAG) !== 0) {
			this.messageContents.write(this.windowsVersion, 64, 8, "hex");
		} else {
			this.messageContents.write("0000000000000000", 64, 8, "hex");
		}

		// TODO :
		// MIC DISABLED BECAUSE OF NEW BUFFER IS NOT EMPTY
		// THE RULE TO APPLY IS NOT CLEAR ! MUST WE DO APPLY THE DIGEST ON THE PARTIAL AUTHENTICATE MESSAGE ?
		// IF YES, WE MUST RESOLVE THE BUFFER'S PROBLEM
		/*
        The message integrity for the NTLM NEGOTIATE_MESSAGE,
        CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.<10>

        <10> Section 2.2.1.3: The MIC field is omitted in Windows NT, Windows 2000, Windows XP, and
        Windows Server 2003.

        3.1.5.1.2 Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
        Set AUTHENTICATE_MESSAGE.MIC to MIC
        */
		//        if (windowsVersions.indexOf(this.windowsVersion) >= windowsVersions.indexOf("060072170000000F")) {
		//            var data, hmac = crypto.createHmac('md5', this.sessionKey);
		//			if (session.connectionType === "connectionOriented") {
		//				data = Buffer.concat([session.negotiateMessage.messageContents, session.challengeMessage.messageContents, this.messageContents]);
		//			} else {
		//				data = Buffer.concat([session.challengeMessage.messageContents, this.messageContents]);
		//			}
		//            const mic = hmac.update(data).digest('hex');
		//            this.messageContents.write(mic, 72, 16, "hex");
		//		} else {
		//			this.messageContents.write("00000000000000000000000000000000", 72, 16, "hex");
		//		}
		// Add payload
		this.messageContents.write(this.lmResp.toString('hex'), lmRespOffset, this.lmResp.length, "hex");
		this.messageContents.write(this.ntResp.toString('hex'), ntRespOffset, this.ntResp.length, "hex");
		this.messageContents.write(this.domainBytes.toString('hex'), domainOffset, this.domainBytes.length, "hex");
		this.messageContents.write(this.userBytes.toString('hex'), userOffset, this.userBytes.length, "hex");
		this.messageContents.write(this.hostBytes.toString('hex'), hostOffset, this.hostBytes.length, "hex");

		// Add session security
		if (this.sessionKey != null) {
			this.messageContents.write(this.sessionKey.toString('hex'), sessionKeyOffset, this.sessionKey.length, "hex");
		} else {
			// Must do it because new Buffer is not empty ?????????
			this.messageContents.write("00000000000000000000000000000000", sessionKeyOffset, 16, "hex");
		}

		return NTLMMessage.prototype.getResponse.call(this);
	}

	stringify() {
		//        console.log("domain: \n\t-offset: "+domainOffset+"\n\t-length: "+this.domainBytes.length+"\n\t-hexa: "+this.domainBytes.toString('hex'));
		//        console.log("user: \n\t-offset: "+userOffset+"\n\t-length: "+this.userBytes.length+"\n\t-hexa: "+this.userBytes.toString('hex'));
		//        console.log("host: \n\t-offset: "+hostOffset+"\n\t-length: "+this.hostBytes.length+"\n\t-hexa: "+this.hostBytes.toString('hex'));
		//        console.log("lm: \n\t-offset: "+lmRespOffset+"\n\t-length: "+this.lmResp.length+"\n\t-hexa: "+this.lmResp.toString('hex'));
		//        console.log("nt: \n\t-offset: "+ntRespOffset+"\n\t-length: "+this.ntResp.length+"\n\t-hexa: "+this.ntResp.toString('hex'));
		//        if (this.sessionKey != null) {
		//			this.messageContents.write(this.sessionKey.toString('hex'), sessionKeyOffset, this.sessionKey.length, "hex");
		//	        console.log("session key: \n\t-offset: "+sessionKeyOffset+"\n\t-length: "+this.sessionKey.length+"\n\thexa: "+this.sessionKey.toString('hex')+"\n\t-expected offset: "+new Buffer("d8000000","hex").readUInt32LE(0));
		//        }	
	}

};