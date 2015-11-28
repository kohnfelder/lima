// Basic crypto functionality, based on forge.
// Copyright 2015 Loren Kohnfelder
// Reference:
// https://npmjs.org/package/node-forge
// http://digitalbazaar.github.io/forge

'use strict';

var util = require('util');
var forge = require('node-forge')({disableNativeCode: true});
var kem = forge.kem;
var md = forge.md;
var pki = forge.pki;
var rsa = pki.rsa;

// Random byte generator. Argument length (in bytes).
function random(length) {
  return forge.random.getBytesSync(length);
}

// Compute SHA256 hash of string str with encoding (utf8 default).
// Returns result as hex string.
function sha256(str, encoding) {
  var digest = md.sha256.create();
  digest.update(str, encoding); // Default "utf8".
  return digest.digest().toHex();
}

// PublicKey object wrapper. Used internally only.
// Param: {type: string, data: key_data}
// Where type is "forge" for forge key object, or "pem" for PEM.
function PublicKey(param) {
  switch (param.type) {
  case "forge":
    this.key = param.data;
    break;
  case "pem":
    this.key = pki.publicKeyFromPem(param.data);
    break;
  default:
    throw new Error("Unexpected type: " + param.type);
  }
}
var proto = PublicKey.prototype;
proto.typename = "PublicKey";
proto.encrypt = function(msg) {return this.key.encrypt(msg);};
proto.decrypt = function(cipher) {return this.key.decrypt(cipher);};
proto.serialize = function() {return pki.publicKeyToPem(this.key);};

// Load public key from serialized form.
function getpublickey(data) {
  return new PublicKey({type: "pem", data: data});
}

// PrivateKey object wrapper. Used internally only.
// Param: {type: string, data: key_data}
// Where type is "forge" for forge key object, or "pem" for PEM.
// TODO: password
function PrivateKey(param) {
  switch (param.type) {
  case "forge":
    this.key = param.data;
    break;
  case "pem":
    if (param.password)
      this.key = pki.decryptRsaPrivateKey(param.data, param.password, {legacy: true});
    else
      this.key = pki.privateKeyFromPem(param.data);
    break;
  default:
    throw new Error("Unexpected type: " + param.type);
  }
}
proto = PrivateKey.prototype;
proto.typename = "PrivateKey";
proto.encrypt = function(msg) {return this.key.encrypt(msg);};
proto.decrypt = function(cipher) {return this.key.decrypt(cipher);};
proto.serialize = function(password) {
  if (password)
    return pki.encryptRsaPrivateKey(this.key, password);
  else
    return pki.privateKeyToPem(this.key);
};

// Load public key from serialized form.
function getprivatekey(data, password) {
  return new PrivateKey({type: "pem", data: data, password: password});
}

// Cryptor uses a wrapped symmetric key for long messages.
// Argument is PublicKey or PrivateKey wrapped forge key.
function Cryptor(asymkey) {
  this.asymkey = asymkey.key;
  var kdf1 = new kem.kdf1(md.sha1.create());
  var kem1 = kem.rsa.create(kdf1);
  this.wrapper = kem1.encrypt(this.asymkey, 16);  // {encapsulation, key}
  this.iv = random(12);
}
proto = Cryptor.prototype;
proto.encrypt = function(msg) {
  var cipher = forge.cipher.createCipher('AES-GCM', this.wrapper.key);
  cipher.start({iv: this.iv});
  cipher.update(forge.util.createBuffer(msg));
  cipher.finish();
  return {encrypted: cipher.output.getBytes(), tag: cipher.mode.tag.getBytes()};
};
proto.getcontext = function() {
  return {iv: this.iv, encapsulation: this.wrapper.encapsulation};
};

// Decryptor takes wrapped symmetric encryption.
// Arguments: PublicKey or PrivateKey wrapped forge key, context from encryption.
function Decryptor(asymkey, context) {
  this.asymkey = asymkey.key;
  this.iv = context.iv;
  this.encapsulation = context.encapsulation;
}
proto = Decryptor.prototype;
proto.decrypt = function(encrypted) {
  var kdf1 = new kem.kdf1(forge.md.sha1.create());
  var kem1 = kem.rsa.create(kdf1);
  var symkey = kem1.decrypt(this.asymkey, this.encapsulation, 16);
  var decipher = forge.cipher.createDecipher('AES-GCM', symkey);
  decipher.start({iv: this.iv, tag: encrypted.tag});
  decipher.update(forge.util.createBuffer(encrypted.encrypted));
  var success = decipher.finish();
  return success ? decipher.output.getBytes() : null;
}

// Generate new key pair, params: {bits: key_size, e: exponent}.
// Returns KeyPair object with {keypair, privatekey, publickey}.
function newkeypair(params) {
  return new KeyPair(params);
}

function KeyPair(params) {
  this.keypair = rsa.generateKeyPair(params || {bits: 2048, e: 0x10001});
  this.privatekey = new PrivateKey({type: "forge", data: this.keypair.privateKey});
  this.publickey = new PublicKey({type: "forge", data: this.keypair.publicKey});
}
proto = KeyPair.prototype;
proto.typename = "KeyPair";

/*
// convert a Forge private key to PEM-format
// (preferred method if you don't want encryption)
var pem = pki.privateKeyToPem(privateKey);

// wraps and encrypts a Forge private key and outputs it in PEM format
// (preferred method if you do want encryption)
var pem = pki.encryptRsaPrivateKey(privateKey, 'password');

// encrypts a Forge private key and outputs it in PEM format using OpenSSL's
// proprietary legacy format + encapsulated PEM headers (DEK-Info)
// (perhaps more compatible with some legacy OpenSSL-based applications)
var pem = pki.encryptRsaPrivateKey(privateKey, 'password', {legacy: true});

// decrypts a PEM-formatted, encrypted private key
var privateKey = pki.decryptRsaPrivateKey(pem, 'password');
*/

exports.tohex = forge.util.bytesToHex;
exports.fromhex = forge.util.hexToBytes;
exports.random = random;
exports.sha256 = sha256;
exports.newkeypair = newkeypair;
exports.getpublickey = getpublickey;
exports.getprivatekey = getprivatekey;
exports.Cryptor = Cryptor;
exports.Decryptor = Decryptor;

/* BONE YARD

var ct = keypair.publicKey.encrypt("Arbitrary Message Here");
keypair.privateKey.decrypt(ct);

// convert a Forge public key to PEM-format
var pem = pki.publicKeyToPem(publicKey);

// convert a PEM-formatted public key to a Forge public key
var publicKey = pki.publicKeyFromPem(pem);

// String to hex conversion for arbitrary byte strings.
function tohex(bytestring) {
  var s = "";
  for (var i = 0; i < bytestring.length; i++) {
    var byte = bytestring.charCodeAt(i);
    var hex = "0" + byte.toString(16);
    s += hex.substring(hex.length - 2);
  }
  return s;
}

// String from hex conversion for arbitrary byte strings.
// Does not error check input string validity.
function fromhex(hexstring) {
  var bytestring = "";
  for (var i = 0; i < hexstring.length; i += 2) {
    var bytecode = parseInt(hexstring.substring(i, i+2), 16);
    bytestring += String.fromCharCode(bytecode);
  }
  return bytestring;
}

 */
