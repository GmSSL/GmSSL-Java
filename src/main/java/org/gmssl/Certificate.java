/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Certificate {

	private byte[] cert;

	public Certificate() {
	}

	public byte[] getBytes() {
		return cert;
	}

	public void importPem(String file) {
		cert = GmSSLJNI.cert_from_pem(file);
	}

	public void exportPem(String file) {
		GmSSLJNI.cert_to_pem(cert, file);
	}

	public byte[] getSerialNumber() {
		return GmSSLJNI.cert_get_serial_number(cert);
	}

	public String[] getIssuer() {
		return GmSSLJNI.cert_get_issuer(cert);
	}

	public String[] getSubject() {
		return GmSSLJNI.cert_get_subject(cert);
	}

	public java.util.Date getNotBefore() {
		return new java.util.Date(GmSSLJNI.cert_get_not_before(cert));
	}

	public java.util.Date getNotAfter() {
		return new java.util.Date(GmSSLJNI.cert_get_not_after(cert));
	}

	public Sm2Key getSubjectPublicKey() {
		return new Sm2Key(GmSSLJNI.cert_get_subject_public_key(cert), Sm2Key.PUBLIC_KEY);
	}

	public boolean verifyByCaCertificate(Certificate caCert, String sm2Id) {
		int ret = GmSSLJNI.cert_verify_by_ca_cert(cert, caCert.getBytes(), sm2Id);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
