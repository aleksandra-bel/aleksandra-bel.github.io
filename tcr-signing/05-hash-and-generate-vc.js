import fs from "fs";
import crypto from "crypto";
import bs58 from "bs58";
import jsonld from "jsonld";
import jsigs from "jsonld-signatures";

import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";

const { sign, purposes } = jsigs;

/* ================= CONFIG ================= */

const ISSUER_DID = "did:web:aleksandra-bel.github.io";
const SUBJECT_DID = "did:web:cluster-a.github.io";
const ORIGIN = "https://aleksandra-bel.github.io";

const TRUST_LIST_PATH = "../trust/trust-list.json";
const VC_TEMPLATE_PATH = "../vc/vc1.json";      // unsigned template
const PRIVATE_KEY_PATH = "./out/ed25519-private.json";

const VC_OUTPUT_PATH = "./out/vc/vc1.json";
const CREATED = "2026-01-09T12:37:57Z";

const documentLoader = jsonld.documentLoaders.node();

/* ================ HELPERS ================= */

function sha256Multihash(bytes) {
    const digest = crypto.createHash("sha256").update(bytes).digest();
    const mh = Buffer.concat([
        Buffer.from([0x12, 0x20]), // sha2-256, 32 bytes
        digest
    ]);
    // TRAIN expects pure base58 multihash, NO multibase prefix
    return bs58.encode(mh);
}

/* ================= MAIN =================== */

async function main() {
    /* 1️⃣ Read trust list EXACTLY as TRAIN hashes it */
    const rawTrustList = fs.readFileSync(TRUST_LIST_PATH);

    /* 2️⃣ Compute TRAIN-compatible hash */
    const trustHash = sha256Multihash(rawTrustList);
    console.log("✅ TRAIN trust-list hash:", trustHash);

    /* 3️⃣ Load VC template */
    const vc = JSON.parse(fs.readFileSync(VC_TEMPLATE_PATH, "utf8"));

    /* 4️⃣ Inject hash + canonical fields */
    vc.issuer = ISSUER_DID;

    vc.credentialSubject = {
        ...vc.credentialSubject,
        id: SUBJECT_DID,
        trustlistURI: `${ORIGIN}/trust/trust-list.json`,
        hash: trustHash
    };

    /* 5️⃣ Remove old proof (MANDATORY) */
    delete vc.proof;

    /* 6️⃣ Load signing key */
    const keyData = JSON.parse(fs.readFileSync(PRIVATE_KEY_PATH, "utf8"));
    const key = await Ed25519VerificationKey2020.from(keyData);

    /* 7️⃣ Sign VC */
    const signedVc = await sign(vc, {
        suite: new Ed25519Signature2020({
            key,
            date: new Date(CREATED)
        }),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
        compactProof: false,
        expansionMap: false
    });

    /* 8️⃣ Write output */
    fs.mkdirSync("./out/vc", { recursive: true });
    fs.writeFileSync(VC_OUTPUT_PATH, JSON.stringify(signedVc, null, 2));

    console.log("✅ VC generated and signed");
    console.log("➡ output:", VC_OUTPUT_PATH);
}

main().catch(err => {
    console.error("❌ ERROR");
    console.error(err);
    process.exit(1);
});
