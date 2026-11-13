# Red Hat npm compromise (June 2026): real signing certificates

Package: `@redhat-cloud-services/types`. Each `.cert.b64` is the base64 DER Fulcio
signing certificate from that version's SLSA provenance.

- `3.4.2` to `3.6.0`: legitimate releases, from npm's attestations API
  (`https://registry.npmjs.org/-/npm/v1/attestations/@redhat-cloud-services%2ftypes@<version>`),
  fetched 2026-11-13. All built from `refs/heads/master`.
- `3.6.1-malicious`: the malicious release, removed from npm. Its certificate
  comes from the Sigstore transparency log, entry
  [1691052570](https://search.sigstore.dev/?logIndex=1691052570), cited in
  BoostSecurity's write-up:
  https://labs.boostsecurity.io/articles/trusted-publishing-untrusted-branch-red-hat-npm/
  Built from the throwaway branch `refs/heads/oidc-61fff775`.

The attestation verified: same repository, same workflow file (`ci.yaml`),
same trigger (`push`), same runner. Only the ref differs.
