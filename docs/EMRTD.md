# eMRTD Document Signer Registry

The `emrtd` registry answers one question for a policy enforcement point (PEP) that has already verified an
electronic passport or ID card: **does this Document Signer Certificate (DSC) chain, for the claimed issuing
state, to a Country Signing CA (CSCA) in our reviewed anchor list?**

The PEP verifies the SOD (signature and data-group hashes) itself and sends only the DSC plus any other
certificates carried in the SOD. The registry never sees the SOD or any personal data.

## Configuration

```yaml
registries:
  emrtd:
    enabled: true
    name: emrtd-csca                          # default: emrtd-csca
    description: "eMRTD CSCA anchors"         # optional
    anchors_dir: /etc/go-trust/emrtd/anchors  # required
    crls_dir: /etc/go-trust/emrtd/crls        # optional
    watch: true                               # reload when files change

policies:
  policies:
    emrtd-document-signer:
      registries: [emrtd-csca]
      constraints:
        require_key_binding: true
        allowed_key_types: [x5c]
```

| Key | Required | Meaning |
|-----|----------|---------|
| `registries.emrtd.enabled` | yes | Enables the registry. |
| `registries.emrtd.name` | no | Registry name, referenced from `policies.<name>.registries`. Default `emrtd-csca`. |
| `registries.emrtd.description` | no | Free text. |
| `registries.emrtd.anchors_dir` | yes | Directory holding the trust anchors (layout below). Startup fails if it is missing. |
| `registries.emrtd.crls_dir` | no | Directory holding CRLs (layout below). Without it no revocation check is made. |
| `registries.emrtd.watch` | no | Reload anchors and CRLs when files change (debounced). If `false`, changes need a restart. |

The registry only answers requests with `action.name` `emrtd-document-signer`. Any other action is denied as
`malformed_request`. The policy block is what routes that action to the registry and requires an x5c key.

## Anchor directory format

```
<anchors_dir>/<ALPHA3>/<anything>.pem     CSCA and link certificates, one or more per file
<crls_dir>/<ALPHA3>/<anything>.crl        optional, DER or PEM
```

- `<ALPHA3>` is the ISO 3166-1 **alpha-3** code of the issuing state, for example `SWE` or `DEU`. The
  directory name is the country.
- Each anchor's subject country (`C`, alpha-2) must correspond to the directory name through an embedded
  ISO 3166 table (249 codes plus `XK`/`XKX`). A mismatch skips the file and logs an error.
- Files may be PEM with one or more certificates. The file name is not interpreted; the reference
  anchor repository names files by the SHA-256 of the DER.
- Point `anchors_dir` at the **approved** tree only. The reference repository
  ([emrtd-trust-anchors](https://github.com/sirosfoundation/emrtd-trust-anchors)) also holds `candidates/` and
  `revoked/` trees, which must never be loaded; use its `export` command to produce a deployable tree.
- Files that cannot be parsed are **skipped and logged** (`emrtd: no valid certificate in anchor file`), never
  treated as trusted. A DSC whose only chain goes through a skipped anchor is denied (`no_anchor`).

### Known parsing limits

Real CSCA certificates often use encodings that Go's X.509 parser rejects. The registry registers
go-cryptoutil's opt-in `ecparams` parser next to `brainpool`, which handles, without ever trusting a
self-described curve:

- ECDSA keys with explicit curve parameters, when they match NIST P-224/P-256/P-384/P-521 or
  brainpoolP256r1/P384r1/P512r1 exactly;
- negative serial numbers;
- RSA keys whose AlgorithmIdentifier lacks the NULL parameters.

Still rejected (the anchor is skipped and logged at load time, so DSCs issued under it are denied with
`no_anchor`): explicit parameters that match no known curve (other curves, twisted Brainpool, wrong generator or
cofactor), an invalid subjectKeyIdentifier, invalid basicConstraints, and a brainpool subject key under an
RSA-PSS signature. Check the load log after every deployment: the startup line `emrtd anchors loaded` reports the
number of countries and anchors actually loaded, which can be lower than the number of files.

## Request

```json
{
  "subject":  {"type": "key", "id": "SWE"},
  "resource": {"type": "x5c", "id": "SWE", "key": ["<DSC base64 DER>", "<extra cert from SOD>"]},
  "action":   {"name": "emrtd-document-signer"},
  "context":  {"signing_time": "2026-09-30T10:00:00Z"}
}
```

- `subject.id`: alpha-3 issuing state. An invalid value is denied as `unknown_country`.
- `resource.key[0]`: the DSC. Further entries are candidate intermediates (link certificates) only. They are
  never anchors, must carry CA basic constraints and `keyCertSign`, and at most 16 certificates are accepted.
- `context.signing_time`: optional RFC 3339 time at which validity is evaluated for every certificate in the
  chain (per ICAO 9303 Part 12 a DSC is judged at signing time). Default is now. A malformed value is denied.
  The value is taken on the caller's word, so the PEP must derive it from a verified SOD, and should be
  careful with a time the signer itself asserts.

## Response

```json
{"decision": true,
 "context": {"reason": {"admin": {
   "csca_sha256": "...", "csca_subject": "...", "dsc_sha256": "...",
   "country": "SWE", "signing_time": "...", "link_sha256": ["..."]}}}}
```

`link_sha256` appears only when link certificates were used. On deny the machine-readable `code` is in
`context.reason.code` (also `context.reason.admin.code`), with human-readable detail in `context.reason.error`:

| Code | Meaning |
|------|---------|
| `unknown_country` | `subject.id` is not a valid alpha-3 code, or no anchors are loaded for it |
| `no_anchor` | No chain to an anchor of that country could be built |
| `chain_invalid` | A signature in the chain does not verify |
| `country_mismatch` | The DSC's subject `C` disagrees with `subject.id`, or it chains only to another country's anchor |
| `expired` / `not_yet_valid` | A certificate in the chain is outside its validity at `signing_time` |
| `bad_key_usage` | The DSC has a `keyUsage` extension without `digitalSignature` |
| `revoked` | A verified CRL lists a certificate in the chain |
| `malformed_request` | Wrong action, bad certificates, bad `signing_time`, unsupported key combination |

A caller must treat anything other than `decision: true` as not trusted, including errors and timeouts.

## Validation rules

- Chain building uses go-cryptoutil signature checking, so brainpool curves and RSA-PSS work. The system
  certificate pool is never used. SHA-1 and MD5 certificate signatures are rejected.
- Issuer names match by bytes, then case-insensitively. AKI/SKI need not match; the signature decides.
- A DSC without a `keyUsage` extension is accepted; if the extension is present (even with no bits set) it must
  include `digitalSignature`. A DSC that is itself a CA (`basicConstraints` cA=true) is refused.
- Anchors are exempt from the CA/`keyCertSign` check; link certificates from the request must be CAs and assert
  `keyCertSign`.
  `pathLenConstraint` is not enforced and chains are limited to 5 certificates.
- Validity is checked for every certificate at `signing_time`.
- Revocation is strict: any entry on a CRL whose signature verifies against the issuer denies the
  certificate, regardless of revocation date and even if the CRL is past `nextUpdate`. CRLs that fail
  signature verification are ignored; with no CRL for an issuer nothing is denied.
- An unparsable CRL file makes startup fail. On reload the previous data stays in use.

## Feeding the registry from the anchor repository

1. Maintain the list in the anchor repository (candidates are reviewed and approved by a human).
2. Run `emrtd-anchors export --out DIR`. It refuses to run if the repository fails its own checks.
3. Deploy `DIR/anchors` as `anchors_dir` and `DIR/crls` as `crls_dir`. With `watch: true` go-trust reloads
   when the files change, so a sync sidecar or a volume refresh is enough.
4. Check the startup log for the loaded country and anchor counts.
