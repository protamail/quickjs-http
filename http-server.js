import * as util from "./lib/httputil.so";
import * as os from "os";
import * as std from "std";
import { see } from "./see.js";
export * from "./see.js";
export * from "./lib/httputil.so";
export { close } from "os";

const MAX_REQUEST_SIZE = 20000000;
var _buf = new ArrayBuffer(4);
var _intBuf = new Uint32Array(_buf);
var _workers = {};
var _listenfd, _minWorkers, _maxWorkers, _timeoutSec;
var _workerProcess = 0, _statusWriteFd, _procLimitTimer, _requestHandler;

os.signal(os.SIGPIPE, function() {
    console.log(`Received SIGPIPE`);
});

os.signal(os.SIGCHLD, function() {
    let pid;
    while ((pid = os.waitpid(-1, os.WNOHANG)[0]) > 0) {
        //dont try to restart anything here because we could be shutting down
        let workerKey = `w${pid}`;
        if (workerKey in _workers) {
            os.setReadHandler(_workers[workerKey].statusReadFd, null);
            os.close(_workers[workerKey].statusReadFd);
            delete _workers[workerKey];
        }
    }
});

const termSignals = [os.SIGQUIT, os.SIGTERM, os.SIGINT, os.SIGABRT];
termSignals.forEach(s => os.signal(s, function collectWorkers() {
    console.log(`Received signal ${s}`);
    shutdown();
}));

export function start({ listen = "::0", port, minWorkers = 1, maxWorkers = 10, workerTimeoutSec = 180, requestHandler }) {
    if (!port)
        throw new Error("Expecting port as number");
    _listenfd = util.listen(listen, port, 10/*backlog*/);
    [_minWorkers, _maxWorkers, _timeoutSec, _requestHandler] = [minWorkers, maxWorkers, workerTimeoutSec, requestHandler];
    if (!Number.isInteger(_minWorkers) || !Number.isInteger(_maxWorkers) ||
        !Number.isInteger(_timeoutSec))
        throw new Error("Expecting minWorkers, maxWorkers, timeoutSec as integer");
    if (_maxWorkers < _minWorkers || _minWorkers > 100)
        throw new Error("Expecting maxWorkers < minWorkers and minWorkers < 100");
    if (!_requestHandler || typeof(_requestHandler) !== "function")
        throw new Error("Expecting requestHandler as function");
    enforceWorkerLimits();
    console.log(`Now serving at http://${listen}:${port}`);
    if (_procLimitTimer)
        os.clearTimeout(_procLimitTimer);
    scheduleProcLimiter();
}

function scheduleProcLimiter() {
    _procLimitTimer = os.setTimeout(function() {
        enforceWorkerLimits();
        scheduleProcLimiter();
    }, 2000);
}

function initChild() {
    for (let workerKey in _workers) {
        os.setReadHandler(_workers[workerKey].statusReadFd, null);
        os.close(_workers[workerKey].statusReadFd);
        delete _workers[workerKey];
    }
    if (_procLimitTimer)
        os.clearTimeout(_procLimitTimer);
    termSignals.forEach(s => os.signal(s, null));
}

export function shutdown() {
    console.log("Shutting down.");
    for (let workerKey in _workers)
        os.kill(_workers[workerKey].pid, os.SIGINT);
    std.exit(0);
}

function enforceWorkerLimits() { //only parent process should return from here
    let workerKeys = Object.keys(_workers);
    let workerCount = workerKeys.length;
    let idleCount = 0;
    let curMs = new Date().getTime();
    let maxIdleOverMin = Math.max(_minWorkers/3, 3);
    for (let workerKey of workerKeys) { //remove timed out
        let worker = _workers[workerKey];
        if (!worker.idle && (curMs - worker.busySince)/1000 > _timeoutSec) {
            os.kill(worker.pid, os.SIGINT);
            workerCount--;
        }
        if (worker.idle)
            idleCount++;
    }
    while (workerCount < _minWorkers) { //ensure min workers
        newWorker();
        workerCount++;
        idleCount++;
    }
    if (!idleCount && workerCount < _maxWorkers) { //ensure at least one idle
        newWorker();
        workerCount++;
        idleCount++;
    } else if (workerCount > _minWorkers && idleCount > maxIdleOverMin) { //remove extra idles
        for (let workerKey of workerKeys) {
            let worker = _workers[workerKey];
            if (worker.idle && workerCount > _minWorkers && idleCount > maxIdleOverMin) {
                os.kill(worker.pid, os.SIGINT);
                workerCount--;
                idleCount--;
            }
        }
    }
}

function newWorker() {
    if (_workerProcess)
        return;
    let statusReadFd;
    [statusReadFd, _statusWriteFd] = os.pipe();
    let pid = util.fork();

    if (pid < 0)
        throw new Error("Failed to fork a process");
    else if (pid > 0) {
        let workerKey = `w${pid}`;
        os.close(_statusWriteFd);
        _workers[workerKey] = {
            pid: pid,
            statusReadFd: statusReadFd,
            idle: 1,
        };
        os.setReadHandler(statusReadFd, () => {
            let c = os.read(statusReadFd, _buf, 0, 4);
            let worker = _workers[workerKey];
            if (c <= 0 || c != 4 || !worker) {
                os.setReadHandler(statusReadFd, null); //child exited
            } else {
                worker.idle = !_intBuf[0];
                if (!worker.idle)
                    worker.busySince = new Date().getTime();
                //console.log(worker.idle? "idle" : "busy");
            }
        });
    } else { //0=child
        _workerProcess = 1;
        try {
            initChild();
            os.close(statusReadFd);
            httpWorker();
        } catch (e) {
            console.log(e);
            console.log(e?.stack);
        } finally {
            std.exit(0); //child is complete
        }
    }
}

export function forkRun(func) {
    let pid = util.fork();

    if (pid < 0)
        throw new Error("Failed to fork a process");
    if (pid == 0) { //child
        try {
            initChild();
            func();
        } catch (e) {
            console.log(e);
            console.log(e?.stack);
        } finally {
            std.exit(0); //child is complete
        }
    }
}

function httpWorker() {
    let connfd, remoteAddr, remotePort;
    let cc=0;
    while(1) { //accept loop
        try {
            [connfd, remoteAddr, remotePort] = util.accept(_listenfd);
//console.log(`accepted from: ${remoteAddr}:${remotePort}`);
            signalStatus(1); //busy
            while(1) { //keep-alive loop
                let r = util.recvHttpRequest(connfd, MAX_REQUEST_SIZE);
                if (!r.method || r.httpMajor != "1") //maybe conn closed or keep-alive limit reached
                    break;
                let [path, query] = r.url && r.url.split("?");
                r.path = path || "";
                r.query = query || "";
                r.originalActionPath = r.path.split("/");
                r.originalActionPath.shift();
                r.actionPath = r.originalActionPath;
                let o = r.p = {};
                for (let kv of r.query.split("&")) {
                    let [k, v] = kv.split("=");
                    o[k] = v && decodeURIComponent(v);
                }
                let resp = _requestHandler(r);
                if (!resp)
                    resp = { status: 403 }; //let backup backend handle it
                resp.httpMinor = r.httpMinor;
                if (!resp.status)
                    resp.status = 200;
                util.sendHttpResponse(connfd, resp);
                if (r.httpMinor != "1")
                    break; //no keep-alive for v1.0
            }
        } catch(e) {
            console.log(e);
            console.log(e?.stack);
        }
        finally {
            if (connfd)
                os.close(connfd);
            signalStatus(0); //idle
        }
    }

    function signalStatus(s) {
        _intBuf[0] = s? 1 : 0;
        let c = os.write(_statusWriteFd, _buf, 0, 4);
        if (c != 4) {
            std.exit(0); //parent exited
        }
    }
}

