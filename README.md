# pcap-socket

Mock TCP socket based on pcap file data.

This module is a pure JavaScript implementation built on top of the
[pcap-parser][] module.

[![Build Status](https://travis-ci.org/wanderview/node-pcap-socket.png)](https://travis-ci.org/wanderview/node-pcap-socket)

## Example

Here is an example test case using a recorded HTTP request to verify that
the typical node.js hello world server responds correctly.

```javascript
'use strict';

var PcapSocket = require('pcap-socket');

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
  psocket.response.on('readable', function() {
    var chunk = psocket.response.read();
    if (chunk) {
      var str = chunk.toString();

      test.ok(str.match(/HTTP\/1.1 200 OK/));
      test.ok(str.match(/Content-Type: text\/plain/));
      test.ok(str.match(new RegExp(msg)));

      test.done();
    }
  });
  psocket.response.read(0);

  // Supply the pcap socket to the HTTP server as a new connection
  server.emit('connection', psocket);
};
```

## TODO

* Do something more intelligent with duplicate and out-of-order TCP packets.

[pcap-parser]: http://www.github.com/nearinfinity/node-pcap-parser

## Class PcapSocket

The PcapSocket class inherits from `Duplex`.  Therefore it provides
both streaming `Readable` and `Writable` interfaces.

### new PcapSocket(pcapSource, address, opts)

* `pcapSource` {String | Stream} If a String, pcapSource is interpreted as
  the name of a pcap file to read from.  Otherwise `pcapSource` is treated
  as a stream providing pcap data.
* `address` {String} An IPv4 address used in the pcap file.  The socket will
  act as that IP address.  Packets sent to this address will be available
  on the socket's `read()` method.
* `opts` {Object | null} Optional parameters
  * `autoHalt` {Boolean} If set to true the socket will automatically `halt()`
    when it sees TCP data sent from the configured local address.  This is
    intended to allow test code the opportunity to read from the `response`
    stream.  Once the response has been verified correct, call `proceed()`
    to restart the flow of data.  Defaults to false.
  * `localPort` {Number | null} The TCP port associated with the `address`
    passed as the second argument.  Packets sent to this port at the given
    address wil be available on the socket's `read()` method.  If not
    provided then the port will be automatically set to the port used on
    the first TCP packet with data.
  * `remoteAddress` {String | null}  The IPv4 address of the remote peer in
    the pcap file's TCP session.  Only packets originating from this address
    will be available via `read()`.  If not set, then the address will be
    automatically configured based on the first TCP packet with data.
  * `remotePort` {Number | null}  The TCP port number of the remote pper in
    the pcap file's TCP session.  Only packets originating from this port
    will be available via `read()`.  If not set, then port will be
    automatically configured based on the first TCP packet with data.

### psocket.halt()

Stop the flow of data.  While halted, no new data will be buffered to be
returned by the `read()` function.  To start the flow of data again, use
`proceed()`.

The term halt is used since `pause()` is associated with the old style
`stream` API.

### psocket.proceed()

Start the flow of data again after `halt()` has been used to stop it.

The term proceed is used since `resume()` is associated with the old style
`stream` API.

### address()
### localAddress
### localPort
### remoteAddress
### remotePort

These properties are provided in order to maintain compatibility with the
[net.Socket][] API.  If the `localPort`, `remoteAddress`, or `remotePort`
are not set via the constructor options, then they will default to either
the address `'0.0.0.0'` or port `0`.  Once a packet is processed they will
then represent the selected TCP session addresses and ports.  If this
change is problematic for your code or tests, then make sure to set the
addresses and ports via the constructor options.

[net.Socket]: http://nodejs.org/api/net.html#net_class_net_socket
