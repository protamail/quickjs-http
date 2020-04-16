export function see(a) {
    var stack = [];
    var ret = [];

    function print_rec(a) {
        var n, i, keys, key, type, s;

        type = typeof(a);
        if (type === "object") {
            if (a === null) {
                ret.push(a);
            } else if (stack.indexOf(a) >= 0) {
                ret.push("[circular]");
            } else {
                stack.push(a);
                let tab = [...Array(stack.length).keys()].map(() => "    ").join("");
                if (Array.isArray(a)) {
                    n = a.length;
                    ret.push("[");
                    for(i = 0; i < n; i++) {
                        if (i !== 0)
                            ret.push(",");
                        ret.push("\n", tab);
                        if (i in a) {
                            print_rec(a[i]);
                        } else {
                            ret.push("<empty>");
                        }
                        if (i > 20) {
                            ret.push("...");
                            break;
                        }
                    }
                    ret.push(" ]");
                } else if (Object.__getClass(a) === "RegExp") {
                    ret.push(a.toString());
                } else {
                    keys = Object.keys(a);
                    n = keys.length;
                    ret.push("{");
                    for(i = 0; i < n; i++) {
                        if (i !== 0)
                            ret.push(",");
                        ret.push("\n", tab);
                        key = keys[i];
                        ret.push(key, ": ");
                        print_rec(a[key]);
                    }
                    ret.push(" }");
                }
                stack.pop(a);
            }
       } else if (type === "string") {
            s = a.__quote();
            if (s.length > 79)
                s = s.substring(0, 75) + "...\"";
            ret.push(s);
        } else if (type === "symbol") {
            ret.push(String(a));
        } else if (type === "function") {
            ret.push("function " + a.name + "()");
        } else {
            ret.push(a);
        }
    }
    print_rec(a)
    return ret.join("");
}


