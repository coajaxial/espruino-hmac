function bitwiseOr0x36(b) {"compiled";
  return b ^ 0x36; }

function bitwiseOr0x5c(b) {"compiled";
  return b ^ 0x5c; }

class HMAC {
  constructor(key, hash, blockSize, outputSize) {
    if ( key.byteLength > blockSize )
      key = hash(key);
    this.hash = hash;
    this.keyLength = Math.max(blockSize, key.byteLength);
    key = new Uint8Array(key, 0, this.keyLength);
    this.oBuf = new Uint8Array(this.keyLength + outputSize);
    this.oBuf.set(key.map(bitwiseOr0x5c).buffer, 0);
    this.iKeyPad = key.map(bitwiseOr0x36).buffer;
  }
  digest(message) {
    const iBuf = new Uint8Array(this.keyLength + message.byteLength);
    iBuf.set(this.iKeyPad, 0);
    iBuf.set(message, this.keyLength);
    this.oBuf.set(this.hash(iBuf), this.keyLength);
    return this.hash(this.oBuf);
  }
}

class HMAC_SHA1 extends HMAC {
  constructor(key) {
    HMAC.call(key, crypto.SHA1, 64, 20);
  }
}

class FixedMessageSizeHMAC extends HMAC {
  constructor(key, messageSize, hash, blockSize, outputSize) {
    HMAC.call(this, key, hash, blockSize, outputSize);
    this.iBuf = new Uint8Array(this.keyLength + messageSize);
    this.iBuf.set(this.iKeyPad, 0);
    delete this.ikeyPad;
  }
  digest(message) {
    this.iBuf.set(message, this.keyLength);
    this.oBuf.set(this.hash(this.iBuf), this.keyLength);
    return this.hash(this.oBuf);
  }
}

class FixedMessageSizeHMAC_SHA1 extends FixedMessageSizeHMAC {
  constructor(key, messageSize) {
    FixedMessageSizeHMAC.call(this, key, messageSize, crypto.SHA1, 64, 20);
  }
}

exports.SHA1 = function(key) {
  return new HMAC_SHA1(key);
}

exports.SHA1Fixed = function(key, messageSize) {
  return new FixedMessageSizeHMAC_SHA1(key, messageSize);
}
