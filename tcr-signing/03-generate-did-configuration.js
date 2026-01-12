import fs from "fs";
import jsonld from "jsonld";
import jsigs from "jsonld-signatures";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";

const { sign, purposes } = jsigs;

const DID = "did:web:aleksandra-bel.github.io";
const ORIGIN = "https://aleksandra-bel.github.io";
const CREATED = "2026-01-08T10:15:27Z"; // you can change

const keyData = JSON.parse(fs.readFileSync("out/ed25519-private.json", "utf8"));
const documentLoader = jsonld.documentLoaders.node();

(async () => {
    const key = await Ed25519VerificationKey2020.from(keyData);

    const linkedDidVC = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        type: ["VerifiableCredential"],
        issuer: DID,
        issuanceDate: "2025-01-01T00:00:00Z",
        expirationDate: "2030-01-01T00:00:00Z",
        credentialSubject: {
            id: DID,
            origin: ORIGIN
        }
    };

    const signed = await sign(linkedDidVC, {
        suite: new Ed25519Signature2020({ key, date: new Date(CREATED) }),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
        compactProof: false,
        expansionMap: false
    });

    const didConfiguration = {
        "@context": "https://identity.foundation/.well-known/did-configuration/v1",
        linked_dids: [signed]
    };

    fs.mkdirSync("out/.well-known", { recursive: true });
    fs.writeFileSync("out/.well-known/did-configuration.json", JSON.stringify(didConfiguration, null, 2));
    console.log("✅ out/.well-known/did-configuration.json generated");
})();
