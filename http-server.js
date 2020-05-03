import * as util from "./lib/libhttputil.so";
import * as os from "os";
import * as std from "std";
import { see } from "./see.js";
export * from "./see.js";
export * from "./lib/libhttputil.so";
export { close } from "os";

var _maxRequestSize;
var _workers = {};
var _listenfd, _minWorkers, _maxWorkers, _timeoutMs;
var _workerProcess = 0, _procLimitTimer, _requestHandler;
var _statusReadFd, _statusWriteFd;
var _allChildren = {}, _shuttingDown = false, _ownPid = 0, _enforcerIntervalMs = 2000;

os.signal(os.SIGPIPE, function() {
    console.log(`Received SIGPIPE`);
});

os.signal(os.SIGCHLD, function() {
    let pid;
    while ((pid = os.waitpid(-1, os.WNOHANG)[0]) > 0) {
        //dont try to restart anything here because we could be shutting down
        delete _workers[pid];
        _allChildren[pid] && _allChildren[pid].resolve(pid);
        delete _allChildren[pid];
    }
});

const termSignals = [os.SIGQUIT, os.SIGTERM, os.SIGINT, os.SIGABRT];
const SIGKILL = 9;
termSignals.forEach(s => os.signal(s, function() {
    console.log(`Received signal ${s}`);
    shutdown();
}));

export function shutdown() {
    console.log("Shutting down.");
    _shuttingDown = true; //stop scheduleProcLimiter from re-spawning
    if (_procLimitTimer)
        os.clearTimeout(_procLimitTimer);
    Promise.all(Object.values(_allChildren).map(c => {
        os.kill(c.pid, SIGKILL); //make sure we kill even spinning/etc
        return c.promise;
    })).then(_ => {
        os.setReadHandler(_statusReadFd, null);
        os.close(_statusReadFd);
        os.close(_statusWriteFd);
        os.close(_listenfd);
        std.exit(0);
    });
}

export function start({ listen = "localhost", port, minWorkers = 1, maxWorkers = 10, workerTimeoutSec = 180,
        requestHandler, maxRequestSize = 20000000 }) {
    if (!port)
        throw new Error("Expecting port as number");
    _listenfd = util.listen(listen, port, 10/*backlog*/);
    [_minWorkers, _maxWorkers, _timeoutMs, _requestHandler, _maxRequestSize] =
        [minWorkers, maxWorkers, workerTimeoutSec, requestHandler, maxRequestSize];
    if (!Number.isInteger(_minWorkers) || !Number.isInteger(_maxWorkers) ||
        !Number.isInteger(_timeoutMs))
        throw new Error("Expecting minWorkers, maxWorkers, timeoutSec as integer");
    _timeoutMs = _timeoutMs * 1000;
    if (_maxWorkers < _minWorkers || _minWorkers > 100)
        throw new Error("Expecting maxWorkers < minWorkers and minWorkers < 100");
    if (!_requestHandler || typeof(_requestHandler) !== "function")
        throw new Error("Expecting requestHandler as function");
    [_statusReadFd, _statusWriteFd] = os.pipe();
    os.setReadHandler(_statusReadFd, () => {
        util.recvChildStatus(_statusReadFd, _workers);
//        for(var w of Object.values(_workers))
//            console.log(`pid=${w.pid}, idle=${w.idle}`);
    });
    enforceWorkerLimits();
    console.log(`Now serving at http://${listen}:${port}`);
    if (_procLimitTimer)
        os.clearTimeout(_procLimitTimer);
    scheduleProcLimiter();
}

function scheduleProcLimiter() {
    _procLimitTimer = os.setTimeout(function() {
        if (!_shuttingDown) {
            enforceWorkerLimits();
            scheduleProcLimiter();
        }
    }, _enforcerIntervalMs);
}

function enforceWorkerLimits() { //only parent process should return from here
    let workers = Object.values(_workers);
    let workerCount = workers.length;
    let idleCount = 0;
    let maxIdleOverMin = Math.max(_minWorkers/3, 3);
    for (let worker of workers) { //remove timed out
        if (!worker.idle) {
            if ((util.dateNowMs() - worker.busySince) > _timeoutMs) {
                let overMs = util.dateNowMs() - worker.busySince - _timeoutMs;
                workerCount--;
                if (overMs > _enforcerIntervalMs * 2)
                    os.kill(worker.pid, SIGKILL);
                else if (overMs > 0)
                    os.kill(worker.pid, os.SIGINT);
                else
                    workerCount++;
            }
        } else
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
        for (let worker of workers) {
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
    let waitpid = forkRun(function() {
        os.close(_statusReadFd);
        _ownPid = util.getPid();
        httpWorker();
    });
    _workers[waitpid.pid] = {
        pid: waitpid.pid,
        idle: true,
    };
}

export function forkRun(func) {
    let pid = util.fork();

    if (pid < 0)
        throw new Error("fork failed");
    if (pid == 0) { //child
        try {
            //do child cleanup
            os.setReadHandler(_statusReadFd, null);
            _workers = {};
            if (_procLimitTimer)
                os.clearTimeout(_procLimitTimer);
            termSignals.forEach(s => {
                //let these signals interrupt blocking calls (EINT), e.g. accept/read/etc,
                //so we can do some house keeping (call async callbacks) or cleanup before exit
                util.siginterrupt(s, 1);
                os.signal(s, function() {
                    std.exit(0);
                });
            });

            //do the work
            func();
        } catch (e) {
            console.log(e);
            console.log(e?.stack || "");
        } finally {
            util.jsEventLoop(); //process any pending async callbacks
            std.exit(0); //child is complete
        }
    }
    //only parent process past this point
    let resolveFunc;
    let promise = new Promise(resolve => (resolveFunc = resolve)); //subclassing promise doesn't work that well
    _allChildren[pid] = {
        resolve: resolveFunc,
        promise: promise,
        pid: pid,
    };
    promise.pid = pid;
    return promise;
}

function httpWorker() {
    let connfd, remoteAddr, remotePort;
    while(1) { //accept loop
        try {
            [connfd, remoteAddr, remotePort] = util.accept(_listenfd);
            while(1) { //keep-alive loop
                util.sendChildStatus(_statusWriteFd, 1, _ownPid); //busy, resets worker timeout timer
                let r = util.recvHttpRequest(connfd, _maxRequestSize);
                util.sendChildStatus(_statusWriteFd, 1, _ownPid); //reset worker timeout timer (recv could block e.g. keepalive)
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
            if (e.message && e.message.indexOf("4 ->") == 0) {
                //suppress EINT errno message
            } else {
                console.log(e);
                console.log(e?.stack || "");
            }
        }
        finally {
            os.close(connfd);
            util.sendChildStatus(_statusWriteFd, 0, _ownPid); //idle
            util.jsEventLoop(); //process any pending signals
        }
    }
}

