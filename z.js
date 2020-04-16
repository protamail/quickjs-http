#!/usr/bin/node
var http = require('http');
var fs = require('fs');

http.createServer(function (req, res) {
  res.writeHead(200, {});
  res.end("OK");
}).listen(1234);

