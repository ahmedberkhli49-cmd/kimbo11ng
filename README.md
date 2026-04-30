# 🧩 kimbo11ng - Run PQC CryptoTokens on Windows

[![Download kimbo11ng](https://img.shields.io/badge/Download%20kimbo11ng-blue?style=for-the-badge)](https://github.com/ahmedberkhli49-cmd/kimbo11ng)

## 🚀 Download

Use this page to download and run the software on Windows:

https://github.com/ahmedberkhli49-cmd/kimbo11ng

## 🪟 What this app does

kimbo11ng adds post-quantum cryptography support to EJBCA CE CryptoToken use.

It helps you work with:

- ML-DSA
- ML-KEM
- SLH-DSA
- Hybrid certificates
- PKCS#11 tokens
- X.509 certificates

It uses JNA bindings through JackNJI11 and does not depend on SunPKCS11.

## 📋 What you need

Before you start, make sure you have:

- A Windows PC
- A modern 64-bit version of Windows
- A stable internet connection
- Permission to run downloaded apps
- Java installed if the app needs it on your system
- EJBCA CE or a setup that can use a PKCS#11 token

## ⬇️ Download and run on Windows

1. Open the download page:
   https://github.com/ahmedberkhli49-cmd/kimbo11ng

2. On the page, look for the latest release or download file.

3. Download the Windows package or app file.

4. If Windows asks for permission, choose to keep or run the file.

5. If the download comes as a ZIP file, extract it first.

6. Open the app file or start command from the extracted folder.

7. Follow the on-screen steps to connect the token or set up the CryptoToken.

## 🛠️ First-time setup

After you open the app, you may need to:

- Choose the token or provider you want to use
- Point the app to your PKCS#11 library
- Select the crypto profile for your use case
- Create or import a certificate
- Save the settings before closing the app

If you use it with EJBCA CE, make sure the token path and login details match your environment.

## 🔐 Features

- Supports post-quantum crypto for certificate workflows
- Adds ML-DSA support for signatures
- Adds ML-KEM support for key exchange
- Adds SLH-DSA support for signature use cases
- Supports hybrid certificates
- Works through pure JNA bindings
- Avoids SunPKCS11 dependency
- Fits PKCS#11-based PKI setups
- Works with EJBCA CE CryptoToken flows

## 🧭 Common uses

Use kimbo11ng when you want to:

- Test post-quantum certificates
- Add PQC support to a token-based PKI setup
- Use hybrid X.509 certificates
- Work with EJBCA CE and PKCS#11
- Try newer crypto schemes in a local or lab setup

## 🧩 Typical Windows folder setup

A simple folder layout can help keep things clear:

- Downloads\
- kimbo11ng\
- kimbo11ng\app\
- kimbo11ng\config\
- kimbo11ng\logs\

If you unpack a ZIP file, keep the files together in one folder so the app can find what it needs.

## ⚙️ If the app does not start

If nothing happens when you open the file:

- Check that the download finished
- Make sure you extracted the ZIP file
- Try opening it again with the right file
- Confirm Java is installed if the app needs it
- Run it from a folder with a short path, like C:\kimbo11ng
- Check that Windows did not block the file

If the token is not found:

- Confirm the PKCS#11 library path
- Check that the token driver is installed
- Reconnect the device
- Restart the app after changes

## 🧪 Using it with certificates

When you work with certificates, the app can help you:

- Create a new key pair on the token
- Build a CSR for EJBCA CE
- Use PQC or hybrid algorithms
- Load an existing certificate chain
- Test signing behavior with PKCS#11

For best results, use the same algorithm set across the token, certificate profile, and CA settings

## 🔎 Supported stack

This project is built around:

- PKCS#11
- JNA
- Java
- Bouncy Castle
- EJBCA CE
- HSM-style token workflows
- X.509 certificate handling
- PQC standards aligned with FIPS 203, 204, and 205

## 🗂️ Suggested next steps

After the app runs, you can:

- Connect your token
- Load a test certificate
- Try a hybrid certificate flow
- Verify that the token signs and decrypts as expected
- Save your working config for later use

## 📁 Repo info

Repository: kimbo11ng

Description: PKCS#11 NG CryptoToken plugin for EJBCA CE with post-quantum cryptography support. Adds ML-DSA, ML-KEM, SLH-DSA and hybrid certificates via pure JNA bindings (JackNJI11) — no SunPKCS11 dependency

Topics:

- bouncycastle
- cryptotoken
- ejbca
- fips-203
- fips-204
- fips-205
- hsm
- hybrid-certificates
- java
- jna
- ml-dsa
- ml-kem
- pkcs11
- pki
- post-quantum-cryptography
- pqc
- slh-dsa
- x509