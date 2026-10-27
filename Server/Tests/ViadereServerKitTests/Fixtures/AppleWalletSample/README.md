# Apple Wallet identity sample (test fixture)

`hpke_envelope.cbor`, `merchant_encryption.key`, `issuer_root.crt`, `session_transcript_parameters.txt`, `session_transcript.txt` and
`info_hash.txt` are copied unchanged from Apple's "identity_verification_sample.zip" (`sample_mdl/`), published at
<https://developer.apple.com/wallet/get-started-with-verify-with-wallet/>. They contain test data only (a test merchant key, a test issuer
root and a test mobile driver's license). Binary values are hex encoded in the sample.

Copyright (c) 2022 Apple Inc. The sample is licensed by Apple under the MIT-style permission notice in its README:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
> the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of
> the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
> LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
> WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The sample's mobile security object is valid from 2022-03-31 to 2023-03-22, so the interop test verifies it at a fixed time in that window.
