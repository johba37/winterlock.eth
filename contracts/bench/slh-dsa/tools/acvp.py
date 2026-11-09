#!/usr/bin/env python3
"""Extract NIST's ACVP known answers for SLH-DSA-SHA2-128s into fixtures/acvp-sha2-128s.json.

    python3 -I tools/acvp.py <sigVer internalProjection.json> <sigGen internalProjection.json> > fixtures/acvp-sha2-128s.json

The inputs are usnistgov/ACVP-Server, gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json and
SLH-DSA-sigGen-FIPS205/internalProjection.json at commit ACVP_COMMIT. Kept: every SLH-DSA-SHA2-128s test case of the
external interface for pure SLH-DSA (with its context) and of the internal interface. HashSLH-DSA (preHash) groups are
left out. sigVer cases carry NIST's verdict; sigGen cases are signatures NIST's implementation made, so all valid.
The secret key and the additional randomness let tools/check_reference.py re-sign them.
"""
import json
import sys

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
SET = "SLH-DSA-SHA2-128s"


def cases(path, mode):
    out = []
    for g in json.load(open(path))["testGroups"]:
        if g["parameterSet"] != SET:
            continue
        iface, pre = g["signatureInterface"], g.get("preHash")
        if not (iface == "internal" or (iface == "external" and pre == "pure")):
            continue
        for t in g["tests"]:
            out.append({
                "source": f"ACVP {mode} tgId {g['tgId']} tcId {t['tcId']}",
                "internal": iface == "internal",
                "pk": "0x" + t["pk"].lower(),
                "message": "0x" + t["message"].lower(),
                "context": "0x" + t.get("context", "").lower(),
                "signature": "0x" + t["signature"].lower(),
                "sk": "0x" + t["sk"].lower(),
                "addrnd": "0x" + t.get("additionalRandomness", "").lower(),
                "valid": t["testPassed"] if mode == "sigVer" else True,
                "reason": t.get("reason", "sigGen, deterministic" if g.get("deterministic") else "sigGen, randomized"),
            })
    return out


if __name__ == "__main__":
    vectors = cases(sys.argv[1], "sigVer") + cases(sys.argv[2], "sigGen")
    json.dump({
        "source": f"usnistgov/ACVP-Server@{ACVP_COMMIT}, gen-val/json-files/SLH-DSA-sig{{Ver,Gen}}-FIPS205/"
                  "internalProjection.json",
        "parameterSet": SET,
        "vectors": vectors,
    }, sys.stdout, indent=1)
    print()
