import r2pipe
import json
infile = r"input.dll"
r2 = r2pipe.open(infile, [])
r2.cmd("aaa")
info = json.loads(r2.cmd("ij"))
entrypoint = info['bin']['baddr']
print("ENTRYPOINT: " + hex(entrypoint))
fcns = json.loads(r2.cmd("aflj"))

def makeops(ops):
    o = []
    for q in ops:
        o.append({
            "address": q['offset'] - entrypoint,
            "size": q['size'],
            "opcode": q['opcode'],
            "type": q['type'],
        })
    o.sort(key = lambda x: x['address'])
    return o

sorted_funcs = []
for f in fcns:
    if f["type"] == "fcn":
        d = json.loads(r2.cmd("pdfj @%s" % f["name"]))
        sorted_funcs.append({
            "name": d['name'],
            "size": d['size'],
            "address": d['addr'] - entrypoint,
            "ops": makeops(d['ops'])
        })
sorted_funcs.sort(key = lambda x: x['address'])

file = open("disassembly.txt", "w+")
for f in sorted_funcs:
    file.write("; function: %s @%08d+%08d\n" % (f['name'], f['address'], f['size']))
    for o in f['ops']:
        file.write("%08d+%02d/%s/: %s\n" % (o['address'], o['size'], o['type'], o['opcode']))
file.close()