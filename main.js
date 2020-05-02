#!/bin/env -S qjs -m
import * as http from "./http-server.js";
import * as os from 'os';

var mainProcName = scriptArgs[0].match(/.*\/(.*)/)[1] || scriptArgs[0];
try {
    http.setProcName(mainProcName);
    http.start({
        listen: "::0",
        port: 1202,
        minWorkers: 2,
        maxWorkers: 20,
        workerTimeoutSec: 600,
        requestHandler: handleRequest,
    });
} catch (e) {
    console.log(e);
    console.log(e?.stack || "");
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

function simpleSendMail(host, port, from, to, subj, text) {
    var conn = http.connect("10.8.1.1", 587);
    assertResp("220 ");
    assertResp("250 ", `ehlo localhost\n`);
    assertResp("250 ", `mail from: ${from}\n`);
    assertResp("250 ", `rcpt to: ${to}\n`);
    assertResp("354 ", "data\n");
    assertResp("250 ", `Subject: ${subj}\r\n\r\n${text}\r\n.\r\n`)
    http.sendString(conn, "quit\n");
    http.close(conn);

    function assertResp(respStart, cmd) {
        if (cmd)
            http.sendString(conn, cmd);
        let resp = http.recvLine(conn);
        if (resp.indexOf(respStart) != 0) {
            while (1) { //could receive multiple lines in response to ehlo
                if (resp.match(/^\d\d\d /mg))
                    break;
                resp += http.recvLine(conn);
            }
            if (!resp.match(new RegExp(`^${respStart}`, "mg")))
                throw new Error(`Unexpected reply: ${resp} in response to: ${cmd}`);
        }
    }
}

//http.forkRun(() => {
//    simpleSendMail("10.8.1.1", 587, "bot@bkmks.com", "aprotasenko@bkmks.com", "test subj", "test email");
//});
/*
http.forkRun(function() {
    try{
    var _listenfd = http.listen("localhost", 1234);
        let [conn, remoteAddr, remotePort] = http.accept(_listenfd);
while(1){
    http.recvLine(conn);
    http.sendString(conn, "two linedsfsdklfjsdlkfjlskdjf;saf;ksjdhfg;dfgh;sdfhg;kjdsfhgkj;dhsfgkjdfhsklhjgkldsjfhgkdsjhfglksdjfhglkdsjhfglkdsjhfgkldsjhfgkldjshfglkjsdhgfkldshfglkjdshfglkdjsfhglkdjsfhglkdsfhglkdsfhgkldsjfhjglkdsfjhglkdsfhglksdfhglkdsfhjfgklsdjhfgdlkshgflkdshjfglksdjhfglksjhdfgklshjdfkjg\n");
}
} catch (e){
    console.log(e);
    console.log(e?.stack);
}
});
http.forkRun(function() {
    try{
    var conn = http.connect("localhost", 1234);
while(1){
    http.sendString(conn, "one line dkfhskdjhflkasdhflkdjshaflkjasdhflkjhsdakjfhiluawehfwuhfasdljkhfklsjdahfkljasdhfkljsdahfkljsadhfklasdhflkjhsdklfjhsdlakjfhlsakdfjhlskajdhflksdhgfkshgikusdfhguksdhfgkjsdhaflkwehlrkjhwelkafhasdlkfhsdlkjflksdgfljhsdgfljkhsdgajhg\n");
    http.recvLine(conn);
}
} catch (e){
    console.log(e);
    console.log(e?.stack);
}
});*/
/*
http.forkRun(function() {
try {
    http.setProcName(`${mainProcName}-forked`);
    for(let i=0;i<100000;i++) {
        var resp = simpleFetchUrl("::1", 1202, {
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


