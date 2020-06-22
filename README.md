# ASN1Decoder
ASN1 DER Decoder for X.509 Certificate

## Requirements

- iOS 9.0+ | macOS 10.10+
- Xcode 9

## Integration

## Usage

### Parse a DER/PEM X.509 certificate

``` objective-c
import <ASN1Decoder/ASN1Decoder.h>


X509Certificate* x509 = [X509Certificate new];
NSError* error;
[rootTLSCert populateCert:[rootCert dataUsingEncoding:NSUTF8StringEncoding] error:&error];
if (error){
    NSLog(@"%@", error);
} else {
    NSString* subject = rootTLSCert.subjectDistinguishedName;
}
```
