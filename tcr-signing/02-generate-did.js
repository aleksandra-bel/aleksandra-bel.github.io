import fs from "fs";

const DID = "did:web:vc-holder.ssi-b.platform.mg3.mdb.osc.live";
const ORIGIN = "https://vc-holder.ssi-b.platform.mg3.mdb.osc.live";
const KEY_ID = `${DID}#key-1`;

const publicJwk = JSON.parse(fs.readFileSync("out/public-jwk.json", "utf8"));

const did = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
    ],
    id: DID,
    verificationMethod: [
        {
            id: KEY_ID,
            type: "JsonWebKey2020",
            controller: DID,
            publicKeyJwk: publicJwk
        }
    ],
    assertionMethod: [KEY_ID],
    service: [
        {
            id: `${DID}#vc`,
            type: "TrustedContent",
            serviceEndpoint: `${ORIGIN}/vc/vc-self.json`
        }
    ]
};

fs.mkdirSync("out/.well-known", { recursive: true });
fs.writeFileSync("out/.well-known/did.json", JSON.stringify(did, null, 2));
console.log("✅ out/.well-known/did.json generated");
