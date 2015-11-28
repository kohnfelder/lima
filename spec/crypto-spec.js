// Test for crypto.js using Jasmine.
// Copyright 2015 Loren Kohnfelder

require('jasmine-expect'); // https://github.com/JamieMason/Jasmine-Matchers

var base = require('../lib/crypto.js');
var fs = require('fs');
var util = require('util');

var sha256 = base.sha256;
var random = base.random;
var tohex = base.tohex;
var fromhex = base.fromhex;
var getpublickey = base.getpublickey;
var getprivatekey = base.getprivatekey;
var newkeypair = base.newkeypair;

var nbits = 2048; // test 512;
var sha256empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

describe("Byte string hex conversion.", function() {
    it("Handles null string to/from.", function() {
	var hex0 = tohex("");
	expect(hex0).toEqual("");
	var byte0 = fromhex(hex0);
	expect(byte0).toEqual("");
      });
    it("Converts known string to/from.", function() {
	var str = "Test!";
	var hex = tohex(str);
	expect(hex).toEqual("5465737421");
	var byte = fromhex(hex);
	expect(byte).toEqual(str);
      });
    it("Converts tricky string to/from.", function() {
	var str = "\x00!\x1f ~\x7f\x80-\xfe\xffx\00";
	var hex = tohex(str);
	expect(hex).toEqual("00211f207e7f802dfeff7800");
	var byte = fromhex(hex);
	expect(byte).toEqual(str);
      });
    it("Converts both cases of hex.", function() {
	var hex = "ffeeddccbbaa0ff00ee00dd00cc00bb00aa0";
	var byte = fromhex(hex);
	expect(tohex(byte).toLowerCase()).toEqual(hex);
	var byte2 = fromhex(hex.toUpperCase());
	expect(tohex(byte2).toUpperCase()).toEqual(hex.toUpperCase());
      });
    it("Handles long string conversions.", function() {
	var str = fromhex(sha256empty);
	expect(str.length).toEqual(sha256empty.length / 2);
	expect(tohex(str).toLowerCase()).toEqual(sha256empty.toLowerCase());
      });
  });

describe("Random byte generator.", function() {
    it("Provides correct length.", function() {
	var r1 = random(16);
	expect(r1.length).toEqual(16);
	var r2 = random(123);
	expect(r2.length).toEqual(123);
      });

    it("Gives different results each time.", function() {
	var len = 64;
	var r1 = random(len);
	expect(r1.length).toEqual(len);
	var r2 = random(len);
	expect(r1).toNotEqual(r2);
      });

    xit("Produces average byte values with good distribution.", function() {
	var k = 140;  // How many random byte strings to sample. More takes time.
	var ratio = 0.5;
	var n = 256;  // Number of byte values possible.
	var histo = new Array(n);
	// Array.apply(null, histo).map(Number.prototype.valueOf, 0);
	for (var i = 0; i < n; i++)
	  histo[i] = 0;
	var total = 0;
	for (var i = 0; i < k; i++) {
	  var rand = random(n);
	  for (var j = 0; j < rand.length; j++) {
	    var byte = rand.charCodeAt(j);
	    histo[byte]++;
	    total += byte;
	  }
	}
	var avg = total/(k*n);
	var mini = 0, maxi = 0;
	for (var i = 1; i < n; i++) {
	  if (histo[i] < histo[mini])
	    mini = i;
	  if (histo[i] > histo[maxi])
	    maxi = i;
	}
	expect(avg).toBeWithinRange(126, 130);
	expect(histo[mini]).toBeWithinRange(histo[maxi]*ratio, histo[maxi]);
	expect(histo[maxi]).toBeWithinRange(histo[mini], histo[mini]/ratio);
      });
  });

describe("Hash algorithm SHA256.", function() {
    it("Empty string hash is well-known constant.", function() {
	var h1 = sha256("");
	var h2 = sha256("");
	expect(h1).toEqual(h2);
	// $ shasum -a 256 </dev/null
	// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	expect(h1).toEqual(sha256empty);
      });

    it("Hashes test string to expected result.", function() {
	// echo This is a test. | shasum -a 256
	var teststr = "This is a test.\n";
	var thehash = "11586d2eb43b73e539caa3d158c883336c0e2c904b309c0c5ffe2c9b83d562a1";
	var h = sha256(teststr);
	expect(h).toEqual(thehash);
      });

    it("Hash is reproducible.", function() {
	var h1 = sha256("");
	var h2 = sha256("");
	expect(h1).toEqual(h2);
	// $ shasum -a 256 </dev/null
	// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	expect(h1).toEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
      });

  });

describe("Asymmetric crypto.", function() {
    var keypair;
    var testmsg = "This is a test.\n";
    var password = "SeekRet!";
    keypair = newkeypair({bits: nbits});
    it("Generates key pair.", function() {
	expect(keypair).toBeDefined();
	expect(keypair.typename).toEqual("KeyPair");
	expect(keypair.publickey.typename).toEqual("PublicKey");
	expect(keypair.privatekey.typename).toEqual("PrivateKey");
      });
    it("Encrypts and decrypts.", function() {
	var cipher = keypair.publickey.encrypt(testmsg);
	var decrypted = keypair.privatekey.decrypt(cipher);
	expect(decrypted).toEqual(testmsg);
      });
    it("Serializes public key and can be reconstituted.", function() {
	var pubkey = keypair.publickey.serialize();
	var newpubkey = getpublickey(pubkey);
	var cipher = newpubkey.encrypt(testmsg);
	var decrypted = keypair.privatekey.decrypt(cipher);
	expect(decrypted).toEqual(testmsg);
      });
    it("Serializes private key and can be reconstituted.", function() {
	var privkey = keypair.privatekey.serialize();
	var newprivkey = getprivatekey(privkey);
	var cipher = keypair.publickey.encrypt(testmsg);
	var decrypted = newprivkey.decrypt(cipher);
	expect(decrypted).toEqual(testmsg);
      });
    it("Serializes private key encrypted and can be reconstituted.", function() {
	var privkey = keypair.privatekey.serialize(password);
	var newprivkey = getprivatekey(privkey, password);
	var cipher = keypair.publickey.encrypt(testmsg);
	var decrypted = newprivkey.decrypt(cipher);
	expect(decrypted).toEqual(testmsg);
      });
    it("Encrypts and decrypts very long messages with wrapped key.", function() {
	var msg = fs.readFileSync(__filename).toString();
	expect(keypair).toBeDefined();
	expect(keypair.publickey).toBeDefined();
	// Wrap keys
	var pubkey = keypair.publickey.serialize();
	var newpubkey = getpublickey(pubkey);
	var privkey = keypair.privatekey.serialize();
	var newprivkey = getprivatekey(privkey);
	// Encryption
	var encryptor = new base.Cryptor(newpubkey);
	var cipher = encryptor.encrypt(msg);
	var context = encryptor.getcontext();
	// Decryption
	var decryptor = new base.Decryptor(newprivkey, context);
	var decrypted = decryptor.decrypt(cipher);
	expect(decrypted).toEqual(msg);
	console.log("FYI: Lengths of things:");
	console.log("pem: pub", pubkey.length, "pem: priv", privkey.length);
	console.log("msg", msg.length, "cipher", cipher.encrypted.toString().length,
		    "tag", cipher.tag.toString().length);
	console.log("context: iv", context.iv.length,
		    "encapsulation", context.encapsulation.length);
      });
  });
