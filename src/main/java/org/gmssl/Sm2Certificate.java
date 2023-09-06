/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm2Certificate {

	private byte[] cert = null;

	public Sm2Certificate() {
		this.cert = null;
	}

	public byte[] getBytes() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		return this.cert;
	}

	public void importPem(String file) {
		if ((this.cert = GmSSLJNI.cert_from_pem(file)) == null) {
			throw new GmSSLException("");
		}
	}

	public void exportPem(String file) {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.cert_to_pem(this.cert, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public byte[] getSerialNumber() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		byte[] serial;
		if ((serial = GmSSLJNI.cert_get_serial_number(this.cert)) == null) {
			throw new GmSSLException("");
		}
		return serial;
	}

	public String[] getIssuer() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		String[] issuer;
		if ((issuer = GmSSLJNI.cert_get_issuer(this.cert)) == null) {
			throw new GmSSLException("");
		}
		return issuer;
	}

	public String[] getSubject() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		String[] subject;
		if ((subject = GmSSLJNI.cert_get_subject(this.cert)) == null) {
			throw new GmSSLException("");
		}
		return subject;
	}

	public java.util.Date getNotBefore() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		return new java.util.Date(GmSSLJNI.cert_get_not_before(this.cert));
	}

	public java.util.Date getNotAfter() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		return new java.util.Date(GmSSLJNI.cert_get_not_after(this.cert));
	}

	public Sm2Key getSubjectPublicKey() {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		long pub_key;
		if ((pub_key = GmSSLJNI.cert_get_subject_public_key(this.cert)) == 0) {
			throw new GmSSLException("");
		}
		boolean has_private_key = false;
		return new Sm2Key(pub_key, has_private_key);
	}

	public boolean verifyByCaCertificate(Sm2Certificate caCert, String sm2Id) {
		if (this.cert == null) {
			throw new GmSSLException("");
		}
		int ret = GmSSLJNI.cert_verify_by_ca_cert(this.cert, caCert.getBytes(), sm2Id);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
