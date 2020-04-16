#!/usr/bin/env -S qjs -m
import * as server from "./http-server.js";

try {
    server.setProcName(scriptArgs[0].match(/[^/]*?\/(.*)/)[1] || scriptArgs[0]);
    server.start({
        listen: "127.0.0.1:1234",
        minWorkers: 2,
        maxWorkers: 20,
        workerTimeoutSec: 30,
    });
} catch (e) {
    console.log(e);
    console.log(e.stack);
    server.stop(); //need to explicitly stop only in case of error
}


