# Windows packaging policy

PRIMEVPN's Windows release is built on GitHub Actions with Go, Node.js,
MSYS2/MinGW, SQLite, Xray, geo data, and the MTProto sidecar.

Third-party OpenSSL installers are **not vendored in the source repository**
and are **not bundled in PRIMEVPN release archives**. The application build
does not execute or directly reference such an installer.

Users who independently need OpenSSL on Windows should obtain it from the
publisher's official distribution page:

- https://slproweb.com/products/Win32OpenSSL.html

Do not place downloaded installers in tracked source. A local-only staging
directory may be used during manual testing:

```text
packaging/windows/vendor/
```

## Removed historical binary

The following inherited binary was removed from tracked source because it
was included only through a wildcard copy of the entire `windows_files`
directory and had no direct build or runtime reference:

```text
windows_files/SSL/Win64OpenSSL_Light-3_6_0.exe
size: 5866530 bytes
sha256: b995a5fbbd9a3d03bf33f974496749e5743abae97e5561b814e1adf72306dce7
```

The checksum is retained for provenance only. PRIMEVPN does not redistribute
or recommend that historical installer.
