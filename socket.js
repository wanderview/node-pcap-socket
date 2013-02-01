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
var Duplex = stream.Duplex;
var PassThrough = stream.PassThrough;
var util = require('util');

var ip = require('ip');
var pcap = require('pcap-parser');

util.inherits(PcapSocket, Duplex);

// TODO: consider moving header parsing into separate modules

function PcapSocket(pcapSource, address, opts) {
  var self = (this instanceof PcapSocket)
           ? this
           : Object.create(PcapSocket.prototype);

  opts = opts || {};

  Duplex.call(self, opts);

  self.response = new PassThrough(opts);
  self.on('finish', self.response.end.bind(self));

  self._reading = true;
  self._halted = false;

  self._address = address;
  self._autoHalt = !!opts.autoHalt;

  self._parser = pcap.parse(pcapSource);
  self._parser.on('packet', self._onData.bind(self));
  self._parser.on('end', self.push.bind(self, null));
  self._parser.on('error', self.emit.bind(self, 'error'));

  return self;
}

PcapSocket.prototype.halt = function() {
  this._halted = true;
  this._pause();
};

PcapSocket.prototype.proceed = function() {
  this._halted = false;
  this._resume();
};

PcapSocket.prototype.setTimeout = function() { };

PcapSocket.prototype._read = function(size, callback) {
  this._resume();
};

PcapSocket.prototype._write = function(chunk, callback) {
  this.response.write(chunk, callback);
};

PcapSocket.prototype._pause = function() {
  if (this._reading) {
    this.reading = false;
    this._parser.stream.pause();
  }
};

PcapSocket.prototype._resume = function() {
  if (!this._reading && !this._halted) {
    this.reading = true;
    this._parser.stream.resume();
  }
};

PcapSocket.prototype._onData = function(packet) {
  var payload = packet.data;

  var ether = this._parseEthernet(payload);
  if (ether.type !== 0x0800) {
    return;
  }

  var iph = this._parseIP(ether.data);
  // Only consider TCP packets without IP fragmentation
  if (!iph || iph.protocol !== 0x06 || iph.mf || iph.offset) {
    return;
  }

  var tcp = this._parseTCP(iph.data);
  if (tcp.data.length < 1) {
    return;
  }

  // auto-stop if we see packets coming from 
  if (this._autoHalt && iph.src === this._address) {
    this.halt();
  }

  if (iph.dst !== this._address) {
    return;
  }

  var room = this.push(tcp.data);
  if (!room) {
    this._pause();
  }
};

PcapSocket.prototype._parseEthernet = function(buf) {
  var offset = 0;

  var dst = buf.slice(offset, offset + 6);
  offset += 6;

  var src = buf.slice(offset, offset + 6);
  offset += 6;

  var type = buf.readUInt16BE(offset);
  offset += 2;

  var data = buf.slice(offset);

  return { dst: dst, src: src, type: type, data: data };
};

PcapSocket.prototype._parseIP = function(buf) {
  var offset = 0;

  var tmp = buf.readUInt8(offset);
  offset += 1;

  var version = (tmp & 0xf0) >> 4;
  if (version != 4) {
    return null;
  }

  var headerLength = (tmp & 0x0f) * 4;

  // skip DSCP and ECN fields
  offset += 1;

  var totalLength = buf.readUInt16BE(offset);
  offset += 2;

  var id = buf.readUInt16BE(offset);
  offset += 2;

  tmp = buf.readUInt16BE(offset);
  offset += 2;

  var flags = (tmp & 0xe000) >> 13;
  var fragmentOffset = tmp & 0x1fff;

  var df = !!(flags & 0x2);
  var mf = !!(flags & 0x4);

  var ttl = buf.readUInt8(offset);
  offset += 1;

  var protocol = buf.readUInt8(offset);
  offset += 1;

  var checksum = buf.readUInt16BE(offset);
  offset += 2;

  var src = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  var dst = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  var data = buf.slice(headerLength);

  return { flags: {df: df, mf: mf}, id: id, offset: fragmentOffset, ttl: ttl,
           protocol: protocol, src: src, dst: dst, data: data };
};

PcapSocket.prototype._parseTCP = function(buf) {
  var offset = 0;

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

  var data = buf.slice(headerLength);

  return { srcPort: srcPort, dstPort: dstPort, seq: seq, ack: ack,
           flags: flags, window: window, data: data };
}
