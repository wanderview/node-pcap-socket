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

module.exports.testData = function(test) {
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

module.exports.testResponse = function(test) {
  test.expect(1);

  var file = path.join(__dirname, 'data', 'netbios-ssn-request-winxp.pcap');

  var psocket = new PcapSocket(file, '192.168.1.2');

  var msg = 'hello world';

  _flow(psocket.response, msg.length, function(chunk) {
    test.equal(msg, chunk.toString());
  });

  _flow(psocket, 209, function(chunk) {
    psocket.write(new Buffer(msg));
  });

  psocket.on('end', function() {
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
