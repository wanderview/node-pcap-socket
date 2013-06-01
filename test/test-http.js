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

// jshint node:true

'use strict';

var PcapSocket = require('../socket');

var http = require('http');
var path = require('path');

module.exports.http = function(test) {
  test.expect(3);

  var msg = 'Hello World\n';

  // Setup an HTTP server to test
  var server = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(msg);
  });

  // Configure the pcap socket to provide real, recorded network data
  var file = path.join(__dirname, 'data', 'http-session-winxp.pcap');
  var psocket = new PcapSocket(file, '10.0.1.6');

  // When the server sends back a response, validate that it makes sense
  psocket.output.on('readable', function() {
    // Read the full response; length determined by looking at pcap file
    var chunk = psocket.output.read(156);
    if (chunk) {
      var str = chunk.toString();

      test.ok(str.match(/HTTP\/1.1 200 OK/));
      test.ok(str.match(/Content-Type: text\/plain/));
      test.ok(str.match(new RegExp(msg)));

      test.done();
    }
  });
  psocket.output.read(0);

  // Supply the pcap socket to the HTTP server as a new connection
  server.emit('connection', psocket);
};
