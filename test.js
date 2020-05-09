#!/bin/env -S qjs -m
import * as http from "./http-server.js";
import * as os from 'os';

var mainProcName = scriptArgs[0].match(/.*\/(.*)/)[1] || scriptArgs[0];
try {
    http.setProcName(mainProcName);
    http.start({
        listen: "localhost",
        port: 1202,
        minWorkers: 1,
        maxWorkers: 20,
        workerTimeoutSec: 300,
        requestHandler: handleRequest,
    });
} catch (e) {
    console.log(e);
    console.log(e?.stack || "");
    http.shutdown(); //shutdown workers
}

function handleRequest(r) {
//    console.log(http.see(r));
    return {
        status: 302,
        h: {
            Host: "localhost",
            "Content-Type": "text/plain; charset=utf-8",
            Location: "https://meet.jit.si/protasenko",
        },
        postprocess: () => {
            simpleSendMail("10.8.1.1", 587, "redirect-notify@bkmks.com", "aprotasenko@bkmks.com",
                `jitsi visited from ${r.h["X-Real-IP"]}`, "Посетители в: https://meet.jit.si/protasenko");
        }
    };
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
    assertResp("250 ", `Subject: ${subj}\nFrom: ${from}\nTo: ${to}\nContent-Type: text/plain; charset=utf-8;\n\n${text}\r\n.\r\n`)
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


