# Responsible Use Policy

This project supports legitimate reverse engineering and binary analysis. The
maintainer's intent is to help with defensive security, interoperability,
malware triage, build verification, and education.

## Authorization Standard

Only analyze software when you have a clear right to do so. Good examples are:

- your own binaries and build artifacts
- employer or client binaries covered by written authorization
- open-source projects whose licenses permit the analysis you are performing
- malware or suspicious files handled for defensive research or incident
  response
- CTF, training, or lab samples intended for reverse engineering practice
- synthetic fixtures created specifically for parser and regression testing

If the authorization is unclear, do not run the tool on that target.

## Not Allowed Here

Do not use this repository, its issues, or its documentation to request or
share help with:

- bypassing licenses, DRM, paid features, or access controls
- recovering proprietary source code without permission
- unpacking protected third-party commercial software without authorization
- redistributing recovered source, secrets, private keys, tokens, or customer
  data
- using extracted credentials for unauthorized access
- evading detection or hiding misuse

## Sharing Data

Do not upload proprietary binaries, customer files, recovered source, secrets,
or private samples to public issues or pull requests.

When reporting parser bugs, prefer:

- synthetic fixtures
- small open-source test programs compiled with a documented Nuitka version
- redacted logs
- hashes, versions, and error messages instead of the target file itself

## Disclosure

If analysis reveals a vulnerability or exposed secret in software you do not
own, follow responsible disclosure. Contact the vendor or owner privately and
avoid publishing exploit details or sensitive recovered material.

## Disclaimer

This policy is not legal advice. You are responsible for complying with local
law, contracts, software licenses, platform terms, and engagement rules.
