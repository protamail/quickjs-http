function Htm(tmpl) {
    let result = [];

    for (var i = 0; i < tmpl.length - 1;) {

        result.push(tmpl[i++]);
        var v = arguments[i];

        if (v instanceof Array) {

            for (var a of v)
                result.push(a instanceof String? a : a == null? "null" : escapeHtml(a.toString()));
        }
        else
            result.push(v instanceof String? v : v == null? "null" : escapeHtml(v.toString()));
    }

    result.push(tmpl[i]);

    return new String(result.join(""));
}

Htm.html = Htm.js = Htm.id = v => new String(v);

function escapeHtml(v) {

    if (v.indexOf("<") == -1 &&
        v.indexOf('"') == -1 &&
        v.indexOf("&") == -1) // no escaping needed
        return v;

    return v.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}


function Run1() {
    var data = {
        a: 1,b:2,c:3,d:4};

//    var r = [];
//    for (var i=0; i<500000;i++)
//     r.push(
return        Htm`dfdsfsdf ${data.a} sdfsdfs ${data.b} sdfsdf ${data.a? data.c : data.d}`;
//    return r.join("");
}

//
//exports.run = Run1;
console.log(Run());

function Run() {
    let j=0;
    for (var i=0; i<500;i++)
        j += Run1().length;
    return j;
}

