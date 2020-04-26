#!/bin/env -S qjs -m
import * as http from "./http-server.js";

var mainProcName = scriptArgs[0].match(/.*\/(.*)/)[1] || scriptArgs[0];
try {
    http.setProcName(mainProcName);
    http.start({
//        listen: "::1",
        port: 1202,
        minWorkers: 2,
        maxWorkers: 20,
        workerTimeoutSec: 600,
        requestHandler: handleRequest,
    });
} catch (e) {
    console.log(e);
    console.log(e?.stack);
    http.shutdown(); //shutdown workers
}

function handleRequest(r) {
//    console.log(http.see(r));
    let resp = {
        h: {
            "Host": "localhost",
            "Content-Type": "text/plain; charset=utf-8",
        },
        body: "OKk",
    };
    return resp;
}

function simpleFetchUrl(host, port, r) {
    var conn = http.connect(host, port);
    http.sendHttpRequest(conn, r);
    var resp = http.recvHttpResponse(conn, r.maxBodySize || -1);
    http.close(conn);
    return resp;
}

/*
http.forkRun(function() {
try {
    http.setProcName(`${mainProcName}-forked`);
    for(let i=0;i<100000;i++) {
        var resp = simpleFetchUrl("127.0.0.1", 1202, {
            url: "/rmt-alex/fmodel1?year=2020&rmtid=6JRC",
            body: "OK",
            h: {
                Host: "localhost"
            }
        });
//        console.log(http.see(resp));
        if (i && !(i%10000))
            console.log(i);
    }
    console.log("done");
} catch (e){
    console.log(e);
    console.log(e?.stack);
}
    //console.log(http.see(resp));
});*/


