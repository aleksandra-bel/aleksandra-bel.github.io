import fs from "fs";

const DID = "did:web:aleksandra-bel.github.io";
const ORIGIN = "https://aleksandra-bel.github.io";
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
            id: `${DID}#vc1`,
            type: "TrustedContent",
            serviceEndpoint: `${ORIGIN}/vc/vc1.json`
        }
    ]
};

fs.mkdirSync("out/.well-known", { recursive: true });
fs.writeFileSync("out/.well-known/did.json", JSON.stringify(did, null, 2));
console.log("✅ out/.well-known/did.json generated");
