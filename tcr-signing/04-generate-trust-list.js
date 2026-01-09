import fs from "fs";

const DID = "did:web:aleksandra-bel.github.io";
const ORIGIN = "https://aleksandra-bel.github.io";

const trustList = {
    "TrustServiceStatusList": {
        "FrameworkInformation": {
            "TSLVersionIdentifier": 1,
            "TSLSequenceNumber": 1,
            "TSLType": "LOCAL",
            "FrameworkOperatorName": { "Name": "Aleksandra Bel" },
            "FrameworkName": { "Name": "Self-Issued VC Trust Framework" },
            "FrameworkScope": "SELF",
            "ListIssueDateTime": "2026-01-08T12:00:00Z"
        },
        "TrustServiceProviderList": {
            "TrustServiceProvider": [
                {
                    "UUID": DID,
                    "TSPName": "Aleksandra Bel",
                    "TSPTradeName": DID,
                    "TSPInformation": {
                        "TSPInformationURI": ORIGIN,
                        "TSPEntityIdentifierList": {
                            "TSPEntityIdentifier": [
                                { "Type": "DID", "Value": DID }
                            ]
                        },
                        "TSPCertificationList": {
                            "TSPCertification": [
                                { "Type": "SelfDeclaration", "Value": `${ORIGIN}/trust/trust-list.json` }
                            ]
                        }
                    },
                    "TSPServices": {
                        "TSPService": [
                            {
                                "ServiceName": "Verifiable Credential Issuer",
                                "ServiceTypeIdentifier": DID,
                                "ServiceCurrentStatus": "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
                                "StatusStartingTime": "2026-01-01T00:00:00Z",
                                "ServiceDefinitionURI": "https://www.w3.org/TR/vc-data-model/",
                                "ServiceDigitalIdentity": {
                                    "DigitalId": {
                                        "DID": `${DID}#key-1`
                                    }
                                },
                                "AdditionalServiceInformation": {
                                    "ServiceBusinessRulesURI": `${ORIGIN}/trust/rules`,
                                    "ServiceGovernanceURI": `${ORIGIN}/trust/governance`,
                                    "ServiceContractType": "SELF",
                                    "ServicePolicySet": `${ORIGIN}/trust/policy`,
                                    "ServiceSchemaURI": "https://www.w3.org/2018/credentials/v1",
                                    "ServiceSupplyPoint": `${ORIGIN}/vc/`
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
};

fs.mkdirSync("out", { recursive: true });
fs.writeFileSync("out/trust-list.json", JSON.stringify(trustList, null, 2));
console.log("✅ out/trust-list.json generated");
