# aleksandra-bel.github.io

# TRAIN Validation – Example Files Guide

This repository stores the **example files** that successfully pass all **TRAIN checks** on the `/validate` endpoint.

The following example files are included:

- `did.json`
- `did-configuration.json`
- `trust-list.json`
- `vc1.json`

These files are generated using scripts located in the `/tcr-signing` folder and are validated using the TRAIN service.

---

## 📁 Folder Structure

Make sure to follow **exactly the same folder structure** as shown below:

```text
.
├── .well-known/
│   └── did-configuration.json
│   └── did.json
├── trust/
│   └── trust-list.json
├── vc/
│   └── vc1.json
```

Here did-configuration and did belong to the **Issuer**, vc1 to the **Holder** and trust-list to the **Issuer**/**Trust Service provider**.

> ⚠️ **Important**  
> TRAIN relies on both file content **and** folder structure, as some of the paths are hard-coded in it.   
> Any deviation may cause validation to fail.

---

## ⚙️ Generating the Example Files

You can generate valid example files by running the scripts in the `/tcr-signing` folder **in numeric order**.

- Scripts must be executed sequentially
- Output files will be written to the `/out` folder
- Copy the generated files into the correct folders shown above

---

## 🔑 DID Requirements

Your DID document **must** follow this structure:

```json
{
  "id": "did:web:aleksandra-bel.github.io#key-1",
  "type": "JsonWebKey2020",
  "controller": "did:web:aleksandra-bel.github.io",
  "publicKeyJwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "…"
  }
}
```

### Mandatory rules

- `type: "JsonWebKey2020"` is **mandatory**
- Field name **must** be `publicKeyJwk`
- The DID **must be resolvable**
- You may change the DID identifier as long as it resolves correctly

---

## 🌐 DID Configuration

- `did-configuration.json` is **mandatory**
- It **must** be placed inside the `/.well-known` folder

```text
./.well-known/did-configuration.json
```

TRAIN validation will fail if this file is missing or misplaced.

---

## 🛡 Trust List Requirements

The **Trust List** must:

- Follow the same structure as the provided example
- Use `ServiceTypeIdentifier` equal to the `issuer` value sent to `/validate`
Example:
```json
"ServiceTypeIdentifier": "did:web:aleksandra-bel.github.io"
```
---

## 📜 Verifiable Credential (VC) Rules

When working with Verifiable Credentials:

1. The `hash` field **must contain the hash of the Trust List** document in bs58 encoding
2. The Trust List referenced by `trustlistURI` must match the hashed file
3. The VC **must be re-signed every time it changes**
4. `credentialSubject.id` can be **any DID value**

> ℹ️ TRAIN does **not** validate `credentialSubject.id`;  
> it trusts the **issuer only**.

---

## ✅ Validation Example

### Request

```bash
curl --location 'http://localhost:8083/tcr/v1/validate' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data '{
  "issuer": "did:web:aleksandra-bel.github.io",
  "did": "did:web:aleksandra-bel.github.io",
  "endpoints": [
    "https://aleksandra-bel.github.io/vc/vc1.json"
  ]
}'
```

---

### Successful Response

```json
{
  "didVerified": true,
  "endpoints": [
    {
      "vcUri": "https://aleksandra-bel.github.io/vc/vc1.json",
      "tlUri": "https://aleksandra-bel.github.io/trust/trust-list.json",
      "trustList": {
        "UUID": "did:web:aleksandra-bel.github.io",
        "TSPName": "Aleksandra Bel",
        "TSPTradeName": "did:web:aleksandra-bel.github.io",
        "TSPInformation": {
          "Address": null,
          "TSPCertificationList": {
            "TSPCertification": [
              {
                "Type": "SelfDeclaration",
                "Value": "https://aleksandra-bel.github.io/trust/trust-list.json"
              }
            ]
          },
          "TSPEntityIdentifierList": {
            "TSPEntityIdendifier": null
          },
          "TSPInformationURI": "https://aleksandra-bel.github.io"
        },
        "TSPServices": {
          "TSPService": [
            {
              "ServiceName": "Verifiable Credential Issuer",
              "ServiceTypeIdentifier": "did:web:aleksandra-bel.github.io",
              "ServiceCurrentStatus": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
              "StatusStartingTime": "2026-01-01T00:00:00Z",
              "ServiceDefinitionURI": "https://www.w3.org/TR/vc-data-model/",
              "ServiceDigitalIdentity": {
                "DigitalId": {
                  "X509Certificate": null,
                  "DID": "did:web:aleksandra-bel.github.io#key-1"
                }
              },
              "AdditionalServiceInformation": {
                "ServiceBusinessRulesURI": "https://aleksandra-bel.github.io/trust/rules",
                "ServiceGovernanceURI": "https://aleksandra-bel.github.io/trust/governance",
                "ServiceIssuedCredentialTypes": null,
                "ServiceContractType": "SELF",
                "ServicePolicySet": "https://aleksandra-bel.github.io/trust/policy",
                "ServiceSchemaURI": "https://www.w3.org/2018/credentials/v1",
                "ServiceSupplyPoint": "https://aleksandra-bel.github.io/vc/"
              }
            }
          ]
        }
      },
      "vcVerified": true
    }
  ]
}
```

---

## 🧠 Summary Checklist

- [x] Correct folder structure
- [x] Resolvable DID
- [x] Mandatory `JsonWebKey2020` key
- [x] DID Configuration in `/.well-known`
- [x] Trust List matches issuer
- [x] VC hash matches Trust List
- [x] VC re-signed after Trust List changes

---

