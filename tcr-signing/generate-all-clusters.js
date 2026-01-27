import fs from "fs";
import crypto from "crypto";
import bs58 from "bs58";
import jsonld from "jsonld";
import jsigs from "jsonld-signatures";

import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";
import { Ed25519Signature2020 } from "@digitalbazaar/ed25519-signature-2020";

const { sign, purposes } = jsigs;

/* ================= CONFIG ================= */
//With expected ingress names in SSI Platform

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
const KEY_ID = `${ISSUER_DID}#key-1`;

// Output folders
const OUT = "./out";
const WELL_KNOWN = `${OUT}/.well-known`;
const TRUST_DIR = `${OUT}/trust`;
const VC_DIR = `${OUT}/vc`;

const documentLoader = jsonld.documentLoaders.node();

/* ================ HELPERS ================= */

function base64url(bytes) {
    return Buffer.from(bytes)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function sha256Multihash(bytes) {
    const digest = crypto.createHash("sha256").update(bytes).digest();
    const mh = Buffer.concat([Buffer.from([0x12, 0x20]), digest]);
    return bs58.encode(mh); // TRAIN: pure base58, NO "z"
}

/* ================= MAIN =================== */

(async () => {
    fs.mkdirSync(WELL_KNOWN, { recursive: true });
    fs.mkdirSync(TRUST_DIR, { recursive: true });
    fs.mkdirSync(VC_DIR, { recursive: true });

    /* ========= 1. KEYS ========= */

    const key = await Ed25519VerificationKey2020.generate({
        id: KEY_ID,
        controller: ISSUER_DID
    });

    // Convert multibase public key -> raw bytes -> JWK x
    const decoded = bs58.decode(key.publicKeyMultibase.slice(1));
    const rawPublicKey = decoded.slice(2); // strip 0xed01

    const publicJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: base64url(rawPublicKey)
    };

    fs.writeFileSync(
        `${OUT}/ed25519-private.json`,
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

    /* ========= 2. DID (Issuer DID doc) ========= */

    const did = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        id: ISSUER_DID,
        verificationMethod: [
            {
                id: KEY_ID,
                type: "JsonWebKey2020",
                controller: ISSUER_DID,
                publicKeyJwk: publicJwk
            }
        ],
        assertionMethod: [KEY_ID],

        // Service endpoints point to VC holders (your setup)
        service: [
            {
                id: `${ISSUER_DID}#vc1`,
                type: "TrustedContent",
                serviceEndpoint: `${HOLDER_A_ORIGIN}/vc/vc1.json`
            },
            {
                id: `${ISSUER_DID}#vc2`,
                type: "TrustedContent",
                serviceEndpoint: `${HOLDER_B_ORIGIN}/vc/vc2.json`
            }
        ]
    };

    fs.writeFileSync(`${WELL_KNOWN}/did.json`, JSON.stringify(did, null, 2));

    /* ========= 3. DID CONFIG (Issuer binds domain <-> DID) ========= */

    const didConfigVC = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        type: ["VerifiableCredential"],
        issuer: ISSUER_DID,
        issuanceDate: "2025-01-01T00:00:00Z",
        expirationDate: "2030-01-01T00:00:00Z",
        credentialSubject: {
            id: ISSUER_DID,
            origin: ISSUER_ORIGIN
        }
    };

    const signedDidConfigVC = await sign(didConfigVC, {
        suite: new Ed25519Signature2020({ key }),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
        compactProof: false,
        expansionMap: false
    });

    fs.writeFileSync(
        `${WELL_KNOWN}/did-configuration.json`,
        JSON.stringify(
            {
                "@context":
                    "https://identity.foundation/.well-known/did-configuration/v1",
                linked_dids: [signedDidConfigVC]
            },
            null,
            2
        )
    );

    /* ========= 4. TRUST LIST (served by issuer at /trust) ========= */

    const trustList = {
        TrustServiceStatusList: {
            FrameworkInformation: {
                TSLVersionIdentifier: 1,
                TSLSequenceNumber: 1,
                TSLType: "LOCAL",
                FrameworkOperatorName: { Name: "SSI Platform Issuer" },
                FrameworkName: { Name: "Self-Issued VC Trust Framework" },
                FrameworkScope: "SELF",
                ListIssueDateTime: "2026-01-08T12:00:00Z"
            },
            TrustServiceProviderList: {
                TrustServiceProvider: [
                    {
                        UUID: ISSUER_DID,
                        TSPName: "SSI Platform Issuer",
                        TSPTradeName: ISSUER_DID,
                        TSPInformation: {
                            TSPInformationURI: ISSUER_ORIGIN,
                            TSPEntityIdentifierList: {
                                TSPEntityIdentifier: [{ Type: "DID", Value: ISSUER_DID }]
                            },
                            TSPCertificationList: {
                                TSPCertification: [
                                    {
                                        Type: "SelfDeclaration",
                                        Value: `${ISSUER_ORIGIN}/trust/trust-list.json`
                                    }
                                ]
                            }
                        },
                        TSPServices: {
                            TSPService: [
                                {
                                    ServiceName: "Verifiable Credential Issuer",
                                    ServiceTypeIdentifier: ISSUER_DID,
                                    ServiceCurrentStatus:
                                        "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
                                    StatusStartingTime: "2026-01-01T00:00:00Z",
                                    ServiceDefinitionURI: "https://www.w3.org/TR/vc-data-model/",
                                    ServiceDigitalIdentity: {
                                        DigitalId: { DID: `${ISSUER_DID}#key-1` }
                                    },
                                    AdditionalServiceInformation: {
                                        ServiceBusinessRulesURI: `${ISSUER_ORIGIN}/trust/rules`,
                                        ServiceGovernanceURI: `${ISSUER_ORIGIN}/trust/governance`,
                                        ServiceContractType: "SELF",
                                        ServicePolicySet: `${ISSUER_ORIGIN}/trust/policy`,
                                        ServiceSchemaURI:
                                            "https://www.w3.org/2018/credentials/v1",
                                        ServiceSupplyPoint: `${ISSUER_ORIGIN}/vc/`
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    };

    const trustListPath = `${TRUST_DIR}/trust-list.json`;
    fs.writeFileSync(trustListPath, JSON.stringify(trustList, null, 2));

    /* ========= 5. VC1 (valid) ========= */

    const trustHash = sha256Multihash(fs.readFileSync(trustListPath));

    const vc1 = {
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
        issuer: ISSUER_DID,
        issuanceDate: "2025-01-01T00:00:00Z",
        credentialSubject: {
            id: SUBJECT_DID_A,
            type: "KubernetesCluster",
            name: "ssi-a",
            trustlistURI: `${ISSUER_ORIGIN}/trust/trust-list.json`,
            hash: trustHash
        }
    };

    const signedVC1 = await sign(vc1, {
        suite: new Ed25519Signature2020({ key }),
        purpose: new purposes.AssertionProofPurpose(),
        documentLoader,
        compactProof: false,
        expansionMap: false
    });

    fs.writeFileSync(`${VC_DIR}/vc1.json`, JSON.stringify(signedVC1, null, 2));

    /* ========= 6. VC2 (intentionally invalid signature) ========= */

    // random key NOT in issuer DID doc, but we force proof.verificationMethod = issuer#key-1
    const randomKey = await Ed25519VerificationKey2020.generate({
        id: KEY_ID,
        controller: ISSUER_DID
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
        issuer: ISSUER_DID,
        issuanceDate: "2025-01-01T00:00:00Z",
        credentialSubject: {
            id: SUBJECT_DID_B,
            type: "KubernetesCluster",
            name: "ssi-b",
            trustlistURI: `${ISSUER_ORIGIN}/trust/trust-list.json`,
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

    fs.writeFileSync(`${VC_DIR}/vc2.json`, JSON.stringify(signedVC2, null, 2));
    console.log("⚠️ vc2.json generated (INTENTIONALLY INVALID SIGNATURE)");

    console.log("✅ ALL FILES GENERATED");
    console.log("Issuer host:", ISSUER_ORIGIN);
    console.log("VC holder A:", HOLDER_A_ORIGIN);
    console.log("VC holder B:", HOLDER_B_ORIGIN);
})();
