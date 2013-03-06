// Copyright (c) 2013, Benjamin J. Kelly ("Author")
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'use strict';

module.exports = PcapSocket;

var stream = require('stream');
// Use core classes for node >= 0.9.6
if (stream.Duplex && stream.PassThrough) {
  var Duplex = stream.Duplex;
  var PassThrough = stream.PassThrough;

// Use readable-stream module for node < 0.9.6
} else {
  var Duplex = require('readable-stream/duplex');
  var PassThrough = require('readable-stream/passthrough');
}

var util = require('util');

var EtherStream = require('ether-stream');
var IpStream = require('ip-stream');
var net = require('net');
var PcapStream = require('pcap-stream');

util.inherits(PcapSocket, Duplex);

function PcapSocket(pcapSource, address, opts) {
  var self = (this instanceof PcapSocket)
           ? this
           : Object.create(PcapSocket.prototype);

  opts = opts || {};

  Duplex.call(self, opts);

  if (!_validAddr(address)) {
    throw(new Error('PcapSocket requires a valid IPv4 address; address [' +
                    address + '] is invalid.'));
  }

  // Public properties required for compatibility with net.Socket
  self.bufferSize = self._readableState.bufferSize;
  self.bytesRead = 0;
  self.bytesWritten = 0;
  self.remoteAddress = _validAddr(opts.remoteAddress)
                     ? opts.remoteAddress : '0.0.0.0';
  self.remotePort = ~~opts.remotePort;
  self.localAddress = address;
  self.localPort = ~~opts.localPort;

  // input streaming pipeline
  self._pstream = new PcapStream(pcapSource);
  self._estream = new EtherStream();
  self._ipstream = new IpStream();
  self._ipstream.on('end', self._onEnd.bind(self));
  self._ipstream.on('error', self.emit.bind(self, 'error'));
  self._pstream.pipe(self._estream).pipe(self._ipstream);

  // output stream
  self.output = new PassThrough(opts);
  self.on('finish', self.output.end.bind(self));

  // start the input pipeline flowing
  process.nextTick(this._flow.bind(this));

  return self;
}

PcapSocket.prototype._read = function(size, callback) {
  if (this._paused) {
    this._paused = false;
    this._flow.bind(this);
  }
};

PcapSocket.prototype._write = function(chunk, encoding, callback) {
  // TODO: remove this once readable-stream gets new _write() API
  if (typeof encoding === 'function') {
    callback = encoding;
  }
  this.bytesWritten += chunk.length;
  this.output.write(chunk, callback);
};

PcapSocket.prototype._flow = function() {
  if (this._paused) {
    return;
  }

  var msg = this._ipstream.read();
  if (!msg) {
    this._ipstream.once('readable', this._flow.bind(this));
    return;
  }

  this._onData(msg);

  return this._flow();
}

PcapSocket.prototype._onData = function(msg) {
  if (msg.ip.protocol !== 'tcp') {
    return;
  }

  try {
    var tcp = this._parseTCP(msg.data, msg.offset);

    // Ignore TCP packets without data
    if (tcp.data.length < 1) {
      return;
    }

    // If our configured remote peer is not involved in this packet,
    // then ignore it.
    if (!this._isRemote(msg.ip.src, tcp.srcPort) &&
        !this._isRemote(msg.ip.dst, tcp.dstPort)) {
      return;
    }

    // If this packet is not destined for our endpoint, ignore it
    if (!this._isLocal(msg.ip.dst, tcp.dstPort)) {
      return;
    }

    this._updateState(msg.ip, tcp);

    // Deliver packet in one of two ways:

    // Duplicate optimization from core node net.Socket class.  If there is
    // an ondata function, call it directly.
    if (typeof this.ondata === 'function') {
      this.ondata(tcp.data, 0, tcp.data.length);
      return;
    }

    // Deliver via normal streams2 push() mechanism.
    var room = this.push(tcp.data);
    if (!room) {
      this._paused = true;
    }
  } catch (error) {
    // silently ignore packets we can't parse
  }
};

PcapSocket.prototype._updateState = function(iph, tcp) {
  this.bytesRead += tcp.data.length;

  // Automatically fill in address information as we see packets.
  // Alternatively, these can be provided up-front in constructor ops.

  if (!_validAddr(this.remoteAddress)) {
    this.remoteAddress = iph.src;
  }

  if (!this.remotePort) {
    this.remotePort = tcp.srcPort;
  }

  if (!this.localPort) {
    this.localPort = tcp.dstPort;
  }
}

PcapSocket.prototype._isRemote = function(address, port) {
  return (!_validAddr(this.remoteAddress) || this.remoteAddress === address) &&
         (!this.remotePort || this.remotePort === port);
};

PcapSocket.prototype._isLocal = function(address, port) {
  return this.localAddress === address &&
         (!this.localPort || this.localPort === port);
};

function _validAddr(address) {
  return net.isIPv4(address) && address !== '0.0.0.0';
}

PcapSocket.prototype._onEnd = function(packet) {
  // Duplicate optimization from core node net.Socket class.  If there is
  // an onend function, call it directly instead of using the normal
  // streams based path.
  if (typeof this.onend === 'function') {
    this.onend();
    return;
  }

  this.push(null);
};

PcapSocket.prototype._parseTCP = function(buf, offset) {
  offset = ~~offset;

  var startOffset = offset;

  var srcPort = buf.readUInt16BE(offset);
  offset += 2;

  var dstPort = buf.readUInt16BE(offset);
  offset += 2;

  var seq = buf.readUInt32BE(offset);
  offset += 4;

  var ack = buf.readUInt32BE(offset);
  offset += 4;

  var tmp = buf.readUInt8(offset);
  offset += 1;

  var headerLength = ((tmp & 0xf0) >> 4) * 4;

  tmp = buf.readUInt8(offset);
  offset += 1;

  var flags = {
    fin: !!(tmp & 0x01),
    syn: !!(tmp & 0x02),
    rst: !!(tmp & 0x04),
    psh: !!(tmp & 0x08),
    ack: !!(tmp & 0x10),
    urg: !!(tmp & 0x20)
  };

  var window = buf.readUInt16BE(offset);
  offset += 2;

  var data = buf.slice(startOffset + headerLength);

  return { srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack,
           flags: flags, window: window, data: data };
}

// API compatibility with net.Socket
PcapSocket.prototype.address = function() {
  return { port: this.localPort, family: 'IPv4', address: this.localAddress };
};

PcapSocket.prototype.destroy = function() {
  this._onEnd();
};

PcapSocket.prototype.setTimeout = function() {};
PcapSocket.prototype.setNoDelay = function() {};
PcapSocket.prototype.setKeepAlive = function() {};
PcapSocket.prototype.unref = function() {};
PcapSocket.prototype.ref = function() {};
