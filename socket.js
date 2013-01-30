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
var util = require('util');

var pcap = require('pcap-parser');

util.inherits(PcapSocket, Duplex);

function PcapSocket(pcapSource, address, opts) {
  var self = (this instanceof PcapSocket)
           ? this
           : Object.create(PcapSocket.prototype);

  opts = opts || {};

  Duplex.call(self, opts);

  self.reading = true;
  self.address = address;

  self.parser = pcap.parse(pcapSource);
  self.parser.on('packet', self._onData.bind(self));

  return self;
}

PcapSocket.prototype._read = function(size, callback) {
  if (!this.reading) {
    this.reading = true;
    this.parser.stream.resume();
  }
};

PcapSocket.prototype._write = function(chunk, callback) {
  this.emit('response', chunk);
  if (typeof callback === 'function') {
    callback();
  }
};

PcapSocket.prototype._onData = function(packet) {
  // TODO: parse and strip headers
  var payload = packet.data;

  // TODO: only push payload if its to the correct address
  // TODO: auto-pause stream if reverse traffic is seen

  var room = this.push(payload);
  if (!room && this.reading) {
    this.reading = false;
    this.parser.stream.pause();
  }
};
