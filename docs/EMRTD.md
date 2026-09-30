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
      emrtd:                        # optional, see "Path length"
        path_len_mode: enforce      # ignore (default) | enforce
        path_len_override: 1        # optional; implies enforce, so not valid with "ignore"
```

| Key | Required | Meaning |
|-----|----------|---------|
| `registries.emrtd.enabled` | yes | Enables the registry. |
| `registries.emrtd.name` | no | Registry name, referenced from `policies.<name>.registries`. Default `emrtd-csca`. |
| `registries.emrtd.description` | no | Free text. |
| `registries.emrtd.anchors_dir` | yes | Directory holding the trust anchors (layout below). Startup fails if it is missing. |
| `registries.emrtd.crls_dir` | no | Directory holding CRLs (layout below). Without it no revocation check is made. |
| `registries.emrtd.watch` | no | Reload anchors and CRLs when files change (debounced). If `false`, changes need a restart. |

| `policies.<name>.emrtd.path_len_mode` | no | `ignore` (default) or `enforce`. See [Path length](#path-length). Any other value fails startup. |
| `policies.<name>.emrtd.path_len_override` | no | Integer >= 0 used instead of a certificate's own `pathLenConstraint`; implies `enforce`. See [Path length](#path-length). |

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
  ISO 3166 table (249 codes plus `XK`/`XKX`). A mismatching **certificate** is skipped and logged; other
  certificates in the same PEM file that match remain eligible as anchors.
- Files may be PEM with one or more certificates. The file name is not interpreted; the reference
  anchor repository names files by the SHA-256 of the DER.
- Point `anchors_dir` at the **approved** tree only. The reference repository
  ([emrtd-trust-anchors](https://github.com/sirosfoundation/emrtd-trust-anchors)) also holds `candidates/` and
  `revoked/` trees, which must never be loaded; use its `export` command to produce a deployable tree.
- `anchors_dir` and `crls_dir` themselves may be symlinks (atomic tree swaps). Anything **below** the root must
  be real: any country-named symlink (whatever it points to), any symlink to a directory, and a
  symlinked or otherwise non-regular (for example a FIFO) `.pem` or `.crl` file, are **refused**. Startup fails (on reload the previous data stays in use)
  instead of silently dropping anchors or revocation data, or trusting a link whose target can change without
  the watcher seeing any event.
- Files that cannot be parsed are **skipped and logged** (`emrtd: no valid certificate in anchor file`), never
  treated as trusted. A DSC whose only chain goes through a skipped anchor is denied (`no_anchor`).

### Known parsing limits

Real CSCA certificates often use encodings that Go's X.509 parser rejects. The registry registers
go-cryptoutil's opt-in `ecparams` parser next to `brainpool`, which handles, without ever trusting a
self-described curve:

- ECDSA keys with explicit curve parameters, when they match NIST P-224/P-256/P-384/P-521 or
  brainpoolP256r1/P384r1/P512r1 exactly;
- negative serial numbers;
- RSA keys whose AlgorithmIdentifier lacks the NULL parameters;
- zero-padded curve constants in explicit parameters (go-cryptoutil v0.7.1);
- a non-DER `cA` BOOLEAN in basicConstraints (go-cryptoutil v0.7.1).

Still rejected (the anchor is skipped and logged at load time, so DSCs issued under it are denied with
`no_anchor`): explicit parameters that match no known curve (other curves, twisted Brainpool, wrong generator or
cofactor), an invalid subjectKeyIdentifier, basicConstraints that are invalid in any other way, and a brainpool subject key under an
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

`link_sha256` appears only when link certificates were used. When the **emrtd registry** denies (with the
documented policy, where it is the only registry), the machine-readable `code` is in `context.reason.code` (also
`context.reason.admin.code`), with human-readable detail in `context.reason.error`. A request can also be
rejected before the registry runs (request validation, a policy check), in which case only `context.reason.error`
is present, and with several denying registries the codes can remain nested in the per-registry results. Always
decide trust from `decision`, never from the presence of a code:

| Code | Meaning |
|------|---------|
| `unknown_country` | `subject.id` is not a valid alpha-3 code, or no anchors are loaded for it |
| `no_anchor` | No chain to an anchor of that country could be built |
| `chain_invalid` | No acceptable certificate path: a signature in the chain does not verify (or uses a refused algorithm), a supplied link certificate is not a valid CA, the path violates an enforced `pathLenConstraint` (see [Path length](#path-length)), or the path search was canceled or hit its work limit |
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
  `pathLenConstraint` is not enforced unless the policy opts in (see [Path length](#path-length)); chains are
  limited to 5 certificates either way.
- Validity is checked for every certificate at `signing_time`.
- Revocation is strict: any entry on a CRL whose signature verifies against the issuer denies the
  certificate, regardless of revocation date and even if the CRL is past `nextUpdate`. CRLs that fail
  signature verification are ignored; with no CRL for an issuer nothing is denied.
- A CRL whose issuer name carries a country `C` that does not match its `crls_dir/<ALPHA3>` directory is refused at
  load (it would otherwise be silently ignored for its own state).
- Delta CRLs (`deltaCRLIndicator`) are not supported and are refused like an unparsable CRL: a delta checked
  without its base would look complete. Provide complete CRLs.
- An unparsable CRL file makes startup fail. On reload the previous data stays in use.

## Path length

By default the registry **ignores** the `basicConstraints` `pathLenConstraint` of anchors and link certificates.
Real CSCAs often carry `pathLenConstraint=0` and still sign link certificates for their successors, so strict
enforcement would reject valid passports. Chains are bounded by the 5-certificate cap instead.

A policy can opt in with the `emrtd` block:

```yaml
policies:
  policies:
    emrtd-document-signer:
      registries: [emrtd-csca]
      emrtd:
        path_len_mode: enforce   # ignore (default) | enforce
        path_len_override: 1     # optional
```

- `path_len_mode: ignore` (or no `emrtd` block): today's behaviour.
- `path_len_mode: enforce`: each certificate's own `pathLenConstraint` is applied to the path
  DSC -> [link certificates] -> CSCA. A certificate without one is unlimited.
- `path_len_override: N` (N >= 0): N is used **instead of** the certificate's own value for every CSCA and link
  certificate that acts as an issuer in the chain, including one that has no `pathLenConstraint`, and the anchor
  itself. It implies `enforce`. Combining it with an explicit `path_len_mode: ignore` is a configuration error.

Semantics follow RFC 5280 section 6.1.4. `pathLenConstraint` is the number of **non-self-issued intermediate CAs**
allowed below the issuer. For the issuer at position *i* of the path, the intermediates are the link
certificates between it and the DSC; the DSC is the end-entity and never counts. A **self-issued** certificate
(issuer DN equal to subject DN, as for a link certificate that certifies a CSCA's new key under its unchanged
name) does not count against the limit. Examples, for DSC -> link -> CSCA (one link):

| CSCA `pathLenConstraint` | Link | Mode / override | Result |
|---|---|---|---|
| 0 | different name | default | allowed |
| 0 | different name | `enforce` | `chain_invalid` |
| 0 | self-issued | `enforce` | allowed |
| 0 | different name | override 1 | allowed |
| any / none | different name | override 0 | `chain_invalid` |

A violation is denied as `chain_invalid` with the offending certificate and the counts in `context.reason.error`.
Other candidate paths are still tried, so a chain that satisfies the limit through another route is accepted.

The mode and override are server-side policy controls: the manager drops any client-supplied
`emrtd_path_len_mode` or `emrtd_path_len_override` from the request context, so a caller can neither set nor
weaken them. (A caller that uses the registry package directly, without the manager, supplies those context keys
itself and is trusted with them.)

**When to use it.** Enforce if your risk assessment wants the issuer's own CA constraints honoured and you have
checked that the CSCAs you anchor behave. Use `path_len_override` to apply one deliberate limit across all
states, for example `1` to allow a single link certificate under any CSCA regardless of what the CSCA
certificate says.

**Rollover caveat.** A CSCA with `pathLenConstraint=0` that has already issued a non-self-issued link certificate
to its successor, or a rollover spanning several link certificates, will be denied under `enforce` without an
override, even though the passports are genuine. Self-issued links (same DN) are unaffected. Before enabling
`enforce`, test with real documents from states mid-rollover, and prefer an override sized for the longest
legitimate chain (the 5-certificate cap still applies).

## Feeding the registry from the anchor repository

1. Maintain the list in the anchor repository (candidates are reviewed and approved by a human).
2. Run `emrtd-anchors export --out DIR`. It refuses to run if the repository fails its own checks.
3. Deploy `DIR/anchors` as `anchors_dir` and `DIR/crls` as `crls_dir`. With `watch: true` go-trust reloads
   when the files change, so a sync sidecar or a volume refresh is enough.
4. Check the startup log for the loaded country and anchor counts.
