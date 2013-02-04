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

var PcapSocket = require('../socket');

var path = require('path');

module.exports.data = function(test) {
  test.expect(2);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var psocket = new PcapSocket(file, '192.168.1.2');

  _flow(psocket, 209, function(chunk) {
    test.ok(chunk);
    test.equal(209, chunk.length);
  });

  psocket.on('end', function() {
    test.done();
  });
};

module.exports.output = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var psocket = new PcapSocket(file, '192.168.1.2');

  var msg = 'hello world';

  _flow(psocket.output, msg.length, function(chunk) {
    test.equal(msg, chunk.toString());
  });

  _flow(psocket, 209, function(chunk) {
    psocket.write(new Buffer(msg));
  });

  psocket.on('end', function() {
    test.done();
  });
};

module.exports.defaultProperties = function(test) {
  test.expect(12);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.2';
  var psocket = new PcapSocket(file, addr);

  test.equal(addr, psocket.localAddress);
  test.equal('0.0.0.0', psocket.remoteAddress);
  test.equal(0, psocket.localPort);
  test.equal(0, psocket.remotePort);

  var obj = psocket.address();
  test.equal(addr, obj.address);
  test.equal(0, obj.port);

  psocket.on('readable', function() {
    test.equal(addr, psocket.localAddress);
    test.equal('192.168.1.7', psocket.remoteAddress);
    test.equal(139, psocket.localPort);
    test.equal(1165, psocket.remotePort);

    var obj = psocket.address();
    test.equal(addr, obj.address);
    test.equal(139, obj.port);

    test.done();
  });
  psocket.read(0);
};

module.exports.setProperties = function(test) {
  test.expect(12);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.2';
  var psocket = new PcapSocket(file, addr, {
    remoteAddress: '192.168.1.7',
    remotePort: 1165,
    localPort: 139
  });

  test.equal(addr, psocket.localAddress);
  test.equal('192.168.1.7', psocket.remoteAddress);
  test.equal(139, psocket.localPort);
  test.equal(1165, psocket.remotePort);

  var obj = psocket.address();
  test.equal(addr, obj.address);
  test.equal(139, obj.port);

  psocket.on('readable', function() {
    test.equal(addr, psocket.localAddress);
    test.equal('192.168.1.7', psocket.remoteAddress);
    test.equal(139, psocket.localPort);
    test.equal(1165, psocket.remotePort);

    var obj = psocket.address();
    test.equal(addr, obj.address);
    test.equal(139, obj.port);

    test.done();
  });
  psocket.read(0);
};

module.exports.remoteAddrFilter = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.2';
  var psocket = new PcapSocket(file, addr, {
    remoteAddress: '192.168.1.100',
  });

  var length = 0;
  psocket.on('readable', function() {
    var chunk = psocket.read();
    if (chunk) {
      length += chunk.length;
    }
  });
  psocket.read(0);

  psocket.on('end', function() {
    test.equal(0, length);
    test.done();
  });
};

module.exports.remotePortFilter = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.2';
  var psocket = new PcapSocket(file, addr, {
    remotePort: 2222
  });

  var length = 0;
  psocket.on('readable', function() {
    var chunk = psocket.read();
    if (chunk) {
      length += chunk.length;
    }
  });
  psocket.read(0);

  psocket.on('end', function() {
    test.equal(0, length);
    test.done();
  });
};

module.exports.localPortFilter = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.2';
  var psocket = new PcapSocket(file, addr, {
    localPort: 137
  });

  var length = 0;
  psocket.on('readable', function() {
    var chunk = psocket.read();
    if (chunk) {
      length += chunk.length;
    }
  });
  psocket.read(0);

  psocket.on('end', function() {
    test.equal(0, length);
    test.done();
  });
};

module.exports.localAddrFilter = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var addr = '192.168.1.100';
  var psocket = new PcapSocket(file, addr, {
    localPort: 137
  });

  var length = 0;
  psocket.on('readable', function() {
    var chunk = psocket.read();
    if (chunk) {
      length += chunk.length;
    }
  });
  psocket.read(0);

  psocket.on('end', function() {
    test.equal(0, length);
    test.done();
  });
};

function _flow(stream, size, callback) {
  var chunk = stream.read(size);
  if (!chunk) {
    stream.once('readable', _flow.bind(null, stream, size, callback));
    return;
  }
  callback(chunk);
}
