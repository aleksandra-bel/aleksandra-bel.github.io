import fs from "fs";
import crypto from "crypto";
import bs58 from "bs58";
import jsonld from "jsonld";
import jsigs from "jsonld-signatures";

import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";

const { sign, purposes } = jsigs;

const documentLoader = jsonld.documentLoaders.node();

// Hosts (deployment targets)
const ISSUER_HOST = "did-issuer.ssi.platform.mg3.mdb.osc.live";
const HOLDER_A_HOST = "vc-holder.ssi-a.platform.mg3.mdb.osc.live";
const HOLDER_B_HOST = "vc-holder.ssi-b.platform.mg3.mdb.osc.live";

// DID:web identifiers
const ISSUER_DID = `did:web:${ISSUER_HOST}`;
const SUBJECT_DID_A = `did:web:${HOLDER_A_HOST}`;
const SUBJECT_DID_B = `did:web:${HOLDER_B_HOST}`;

// Origins (HTTPS)
const ISSUER_ORIGIN = `https://${ISSUER_HOST}`;
const HOLDER_A_ORIGIN = `https://${HOLDER_A_HOST}`;
const HOLDER_B_ORIGIN = `https://${HOLDER_B_HOST}`;

// Key id in issuer DID doc
const KEY_ID = `${SUBJECT_DID_B}#key-1`;
const TRUST_LIST_PATH = "./out/trust/trust-list.json";
const PRIVATE_KEY_PATH = "./out/ed25519-private.json";

const OUT = "./out";
const WELL_KNOWN = `${OUT}/.well-known`;
const TRUST_DIR = `${OUT}/trust`;
const VC_DIR = `${OUT}/vc`;

async function main() {
    const rawTrustList = fs.readFileSync(TRUST_LIST_PATH);
    const trustHash = sha256Multihash(rawTrustList);
    console.log("✅ TRAIN trust-list hash:", trustHash);

//     const vc1 = {
//         "@context": [
//             "https://www.w3.org/2018/credentials/v1",
//             {
//                 name: "https://example.org/schema#name",
//                 type: "@type",
//                 trustlistURI: {
//                     "@id": "https://example.org/schema#trustlistURI",
//                     "@type": "@id"
//                 },
//                 hash: "https://example.org/schema#hash",
//                 KubernetesCluster: "https://example.org/schema#KubernetesCluster"
//             },
//             "https://w3id.org/security/suites/ed25519-2020/v1"
//         ],
//         type: ["VerifiableCredential"],
//         issuer: SUBJECT_DID_A,
//         issuanceDate: "2025-01-01T00:00:00Z",
//         credentialSubject: {
//             id: SUBJECT_DID_A,
//             type: "KubernetesCluster",
//             name: "ssi-a",
//             trustlistURI: `${HOLDER_A_ORIGIN}/trust/trust-list.json`,
//             hash: trustHash
//         }
//     };
//
//     const keyData = JSON.parse(fs.readFileSync(PRIVATE_KEY_PATH, "utf8"));
//     const key = await Ed25519VerificationKey2020.from(keyData);
//
//     const signedVC1 = await sign(vc1, {
//         suite: new Ed25519Signature2020({key}),
//         purpose: new purposes.AssertionProofPurpose(),
//         documentLoader,
//         compactProof: false,
//         expansionMap: false
//     });
//
//     fs.mkdirSync("./out/vc", { recursive: true });
//     fs.writeFileSync(`${VC_DIR}/vc-self.json`, JSON.stringify(signedVC1, null, 2));
//     console.log("✅ VC generated and signed");
// }
    /* ========= 6. VC2 (intentionally invalid signature) ========= */

    // random key NOT in issuer DID doc, but we force proof.verificationMethod = issuer#key-1
    const randomKey = await Ed25519VerificationKey2020.generate({
        id: KEY_ID,
        controller: SUBJECT_DID_B
    });

    const vc2 = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            {
                name: "https://example.org/schema#name",
                type: "@type",
                trustlistURI: {
                    "@id": "https://example.org/schema#trustlistURI",
                    "@type": "@id"
                },
                hash: "https://example.org/schema#hash",
                KubernetesCluster: "https://example.org/schema#KubernetesCluster"
            },
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        type: ["VerifiableCredential"],
        issuer: SUBJECT_DID_B,
        issuanceDate: "2025-01-01T00:00:00Z",
        credentialSubject: {
            id: SUBJECT_DID_B,
            type: "KubernetesCluster",
            name: "ssi-b",
            trustlistURI: `${HOLDER_B_ORIGIN}/trust/trust-list.json`,
            hash: trustHash
        }
    };

    const signedVC2 = await sign(vc2, {
        suite: new Ed25519Signature2020({
            key: randomKey,
            verificationMethod: KEY_ID
        }),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
        compactProof: false,
        expansionMap: false
    });

    fs.writeFileSync(`${VC_DIR}/vc-self.json`, JSON.stringify(signedVC2, null, 2));
    console.log("⚠️ VC generated (INTENTIONALLY INVALID SIGNATURE)");
}

function sha256Multihash(bytes) {
    const digest = crypto.createHash("sha256").update(bytes).digest();
    const mh = Buffer.concat([
        Buffer.from([0x12, 0x20]), // sha2-256, 32 bytes
        digest
    ]);
    // TRAIN expects pure base58 multihash, NO multibase prefix
    return bs58.encode(mh);
}

main().catch(err => {
    console.error("❌ ERROR");
    console.error(err);
    process.exit(1);
});