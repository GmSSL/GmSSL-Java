/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Random {

	public Random() {
	}

	public byte[] randBytes(int len) {
		byte[] out = new byte[len];
		if (GmSSLJNI.rand_bytes(out, 0, len) != 1) {
			throw new GmSSLException("");
		}
		return out;
	}

	public void randBytes(byte[] out, int offset, int len) {
		if (out == null
			|| offset < 0
			|| len < 0
			|| offset + len <= 0
			|| out.length < offset + len) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.rand_bytes(out, offset, len) != 1) {
			throw new GmSSLException("");
		}
	}
}
