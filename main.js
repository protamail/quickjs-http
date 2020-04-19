#!/opt/app/workload/addon/gcc/bin/qjs -m
import * as server from "./http-server.js";
import * as os from "os";

try {
    server.setProcName(scriptArgs[0].match(/.*\/(.*)/)[1] || scriptArgs[0]);
    server.start({
        listen: "0.0.0.0:1202",
        minWorkers: 2,
        maxWorkers: 20,
        workerTimeoutSec: 30,
    });
} catch (e) {
    console.log(e);
    console.log(e?.stack);
    server.shutdown(); //shutdown workers
}

/*server.forkRun(function() {
try {
    for(let i=0;i<100000;i++) {
        var conn = server.connect("127.0.0.1", "1202");
        server.send(conn, "GET /rmt-alex/fmodel1?year=2020&rmtid=6JRC HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
        var resp = server.recvHttpResponse(conn, 1000000);
//        console.log(server.see(resp));
        server.close(conn);
        if (i && !(i%10000))
            console.log(i);
    }
    console.log("done");
} catch (e){
    console.log(e);
}
    //console.log(server.see(resp));
});
*/

