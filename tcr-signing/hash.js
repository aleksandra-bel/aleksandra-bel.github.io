
import fs from "fs";
import crypto from "crypto";
import bs58 from "bs58";


const TRUST_LIST_PATH = "./out/trust/trust-list.json";

async function main() {
    const rawTrustList = fs.readFileSync(TRUST_LIST_PATH);
    const trustHash = sha256Multihash(rawTrustList);
    console.log("✅ TRAIN trust-list hash:", trustHash);
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