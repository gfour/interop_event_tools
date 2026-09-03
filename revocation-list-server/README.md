Create and serve a Certificate Revocation List (.crl file).

## Create CRL

We assume that there is a private key in the parent directory (the create_iaca.sh script has run).

```bash
./create_crl.sh
```

## Serve CRL

```bash
./start-revocation-list-server.sh
```
