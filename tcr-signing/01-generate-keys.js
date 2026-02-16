import fs from "fs";
import bs58 from "bs58";
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";

function base64url(bytes) {
    return Buffer.from(bytes)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

const DID = "did:web:vc-holder.ssi-b.platform.mg3.mdb.osc.live";
const KEY_ID = `${DID}#key-1`;

(async () => {
    const key = await Ed25519VerificationKey2020.generate({
        id: KEY_ID,
        controller: DID
    });

    // multibase(base58btc(multicodec + rawKey))
    const decoded = bs58.decode(key.publicKeyMultibase.slice(1));

    // Ed25519 multicodec prefix = 0xed 0x01
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
        throw new Error("Unexpected multicodec prefix, expected Ed25519 (0xed 0x01)");
    }

    // strip multicodec prefix → raw 32-byte Ed25519 key
    const rawPublicKey = decoded.slice(2);

    if (rawPublicKey.length !== 32) {
        throw new Error(`Unexpected raw Ed25519 key length: ${rawPublicKey.length}`);
    }

    const publicJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: base64url(rawPublicKey)
    };

    fs.mkdirSync("out", { recursive: true });

    fs.writeFileSync(
        "out/ed25519-private.json",
        JSON.stringify(
            {
                id: key.id,
                controller: key.controller,
                type: key.type,
                publicKeyMultibase: key.publicKeyMultibase,
                privateKeyMultibase: key.privateKeyMultibase
            },
            null,
            2
        )
    );

    fs.writeFileSync("out/public-jwk.json", JSON.stringify(publicJwk, null, 2));

    console.log("✅ Ed25519 keys generated");
    console.log("publicKeyJwk =", publicJwk);
    console.log("❌ DO NOT COMMIT out/ed25519-private.json");
})();
