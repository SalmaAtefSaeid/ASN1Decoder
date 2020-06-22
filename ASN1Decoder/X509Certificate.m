//
//  X509Certificate.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "X509Certificate.h"
#import "NSArray+HigherOrderFunctions.h"
#import "ASN1DERDecoder.h"
#import "NSData+IntValue.h"

typedef enum X509BlockPosition : NSInteger {
    version      = 0,
    serialNumber = 1,
    signatureAlg = 2,
    issuer       = 3,
    dateValidity = 4,
    subject      = 5,
    publicKey    = 6,
    extensions   = 7
} X509BlockPosition;

NSString* const OID_KeyUsage         = @"2.5.29.15";
NSString* const OID_ExtendedKeyUsage = @"2.5.29.37";
NSString* const OID_SubjectAltName   = @"2.5.29.17";
NSString* const OID_IssuerAltName    = @"2.5.29.18";
NSString* const beginPemBlock = @"-----BEGIN CERTIFICATE-----";
NSString* const endPemBlock   = @"-----END CERTIFICATE-----";


@interface ASN1Object (extension)
- (ASN1Object*)subscript:(X509BlockPosition)index;
@end

@implementation ASN1Object (extension)

- (ASN1Object*)subscript:(X509BlockPosition)index {
    return (self.sub && (index < self.sub.count)) ? self.sub[index] : nil;
}

@end

@interface X509Certificate()

@property (nonatomic, strong) NSArray<ASN1Object *>* asn1;
@property (readonly, strong) NSData* sigAlgParams;
@property (readonly, strong) NSString* sigAlgOID;
@property (readonly, strong) NSString* sigAlgName;
@property (readonly, strong) NSDate* notAfter;
@property (readonly, strong) NSDate* notBefore;
@property (readonly, strong) NSArray<NSString*>* issuerOIDs;
@property (readonly, strong) NSString* issuerDistinguishedName;
@property (readonly, strong) NSArray<NSString *>* subjectOIDs;
@property (readonly, strong) NSData* serialNumber;
@property (readonly, strong) NSNumber* versionNumber;
@property (readonly, strong) NSArray<NSNumber *>* keyUsage;
@property (readonly, strong) NSArray<NSString *>* extendedKeyUsage;
@property (readonly, strong) NSArray<NSString *>* subjectAlternativeNames;
@property (readonly, strong) NSArray<NSString *>* issuerAlternativeNames;
@property (readonly, strong) NSArray<NSString *>* criticalExtensionOIDs;
@property (readonly, strong) NSArray<NSString *>* nonCriticalExtensionOIDs;
@property (readonly, strong) NSArray<ASN1Object *>* extensionBlocks;

@end

@implementation X509Certificate

- (instancetype)init
{
    self = [super init];
    if (self) {
        _asn1 = [NSArray array];
        _block1 = [ASN1Object new];
    }
    return self;
}

- (void)populateCert:(NSData *)data error:(NSError * __autoreleasing *)error {
    NSError * error1;
    [self initializeWithData:data error:&error1];
    if (error1) {
        *error = error1;
    }
}

- (void)initializeWithData:(NSData *)data error:(NSError * __autoreleasing *)error {
    NSString *x509CertificateString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSError * error1;
    if (x509CertificateString && [x509CertificateString containsString:beginPemBlock]) {
        [self initWithPem:data error:&error1];
    } else {
        [self initializeWithDer:data error:&error1];
    }
    if (error1) {
        *error = error1;
    }
}

- (void)initializeWithDer:(NSData *)der error:(NSError * __autoreleasing *)error {
    NSError * error1;
    _asn1 = [ASN1DERDecoder decode:der error:&error1];
    if (error1) {
        *error = error1;
        return;
    }
    if (_asn1.count > 0) {
        ASN1Object * block1 = [[_asn1 firstObject] sub:0];
        if (block1) {
            self.block1 = block1;
            return;
        }
    }
    *error = [[NSError alloc] initWithDomain:@"parseError" code:0 userInfo:nil];
}

- (void)initWithPem:(NSData *)pem error:(NSError * __autoreleasing *)error {
    NSData *derData = [self decodeToDER:pem];
    if (!derData) {
        *error = [[NSError alloc] initWithDomain:@"parseError" code:0 userInfo:nil];
        return;
    }
    NSError * error1;
    [self initializeWithDer:derData error:&error1];
    if (error1) {
        *error = error1;
    }
}

- (void)initWithASN1:(ASN1Object *)asn1 error:(NSError * __autoreleasing *)error {
    ASN1Object *block1 = [asn1 sub:0];
    if (!block1) {
        *error = [[NSError alloc] initWithDomain:@"parseError" code:0 userInfo:nil];
        return;
    }
    self.asn1 = @[asn1];
    self.block1 = block1;
}

/// Checks that the given date is within the certificate's validity period.
- (BOOL)checkValidity:(NSDate *)date {
    NSDate* notBefore = self.notBefore;
    NSDate* notAfter = self.notAfter;
    if (notBefore && notAfter) {
        
        BOOL isDateLaterThanNotBefore = ( [date compare:notBefore] == NSOrderedDescending );
        BOOL isDateEarlierThanNotAfter = ( [date compare:notAfter] == NSOrderedAscending );
        return isDateLaterThanNotBefore && isDateEarlierThanNotAfter;
    }
    
    return false;
}

/// Gets the version (version number) value from the certificate.
- (NSNumber *)versionNumber {
    NSData * v = [X509Certificate firstLeafValue:_block1];
    NSNumber* i = [v toIntValue];

    if (v && i) {
        return [NSNumber numberWithInt: [i unsignedIntValue] +1];
    }
    return nil;
}


/// Gets the serialNumber value from the certificate.
- (NSData *)serialNumber {
    ASN1Object* asn1Obj = [_block1 subscript:serialNumber];
    if (asn1Obj) {
        NSData *result = [asn1Obj value];
        return result;
    }
    return nil;
}

/// Returns the issuer (issuer distinguished name) value from the certificate as a String.
- (NSString *)issuerDistinguishedName {
    ASN1Object * issuerBlock = [_block1 subscript:issuer];
    if (issuerBlock) {
        return [self blockDistinguishedName:issuerBlock];
    }
    return nil;
}

- (NSArray<NSString *> *)issuerOIDs {
    NSMutableArray<NSString *> * result = [NSMutableArray array];
    ASN1Object *subjectBlock = [_block1 subscript:issuer];
    if (subjectBlock.sub == nil) {
        subjectBlock.sub = [NSArray array];
    }
    for (ASN1Object * sub in subjectBlock.sub) {
        NSString *value = [X509Certificate firstLeafValue: sub];
        if (value) {
            [result addObject:value];
        }
    }
    return [NSArray arrayWithArray:result];
}

- (NSString *)issuer:(NSString *)oid {
    ASN1Object *subjectBlock = [_block1 subscript:issuer];
    if (subjectBlock) {
        ASN1Object *oidBlock = [subjectBlock findOid:oid];
        if (oidBlock) {
            ASN1Object *parent = [oidBlock parent];
            if (parent) {
                NSArray<ASN1Object *> * subASN1Object = [parent sub];
                if (subASN1Object) {
                    return [subASN1Object lastObject].value;
                }
            }
        }
    }
    return nil;
}

/// Returns the subject (subject distinguished name) value from the certificate as a String.
- (NSString *)subjectDistinguishedName {
    ASN1Object * issuerBlock = [_block1 subscript:subject];
    if (issuerBlock) {
        return [self blockDistinguishedName:issuerBlock];
    }
    return nil;
}

- (NSArray<NSString *> *)subjectOIDs {
    NSMutableArray<NSString *> * result = [NSMutableArray array];
    ASN1Object *subjectBlock = [_block1 subscript:subject];
    if (subjectBlock) {
        NSArray<ASN1Object *> * array = subjectBlock.sub;
        if (!array) {
            array = [NSArray array];
        }
        for (ASN1Object * sub in array) {
            NSString * value = [X509Certificate firstLeafValue:sub];
            if (value) {
                [result addObject:value];
            }
        }
    }
    return result;
}

- (NSString *)subject:(NSString *)oid {
    ASN1Object *subjectBlock = [_block1 subscript:subject];
    if (subjectBlock) {
        ASN1Object *oidBlock = [subjectBlock findOid:oid];
        if (oidBlock) {
            ASN1Object *parent = [oidBlock parent];
            if (parent) {
                NSArray<ASN1Object *> * subASN1Object = [parent sub];
                if (subASN1Object) {
                    return [subASN1Object lastObject].value;
                }
            }
        }
    }
    return nil;
}

/// Gets the notBefore date from the validity period of the certificate.
- (NSDate *)notBefore {
    ASN1Object * asn1Obj = [_block1 subscript:dateValidity];
    if (asn1Obj) {
        ASN1Object * subASN1Object = [asn1Obj sub:0];
        if (subASN1Object) {
            NSDate * result = [subASN1Object value];
            return result;
        }
    }
    return nil;
}

/// Gets the notAfter date from the validity period of the certificate.
- (NSDate *)notAfter {
    ASN1Object * asn1Obj = [_block1 subscript:dateValidity];
    if (asn1Obj) {
        ASN1Object * subASN1Object = [asn1Obj sub:1];
        if (subASN1Object) {
            NSDate * result = [subASN1Object value];
            return result;
        }
    }
    return nil;
}

/// Gets the signature value (the raw signature bits) from the certificate.
- (NSData *)signature {
    ASN1Object * subASN1Object = [_asn1[0] sub:2];
    if (subASN1Object) {
        NSData * result = [subASN1Object value];
        return result;
    }
    return nil;
}

/// Gets the signature algorithm name for the certificate signature algorithm.
- (NSString *)sigAlgName {
    if (self.sigAlgOID) {
        return [[ASN1Object oidDecodeMap] objectForKey:self.sigAlgOID];
    } else {
        return [[ASN1Object oidDecodeMap] objectForKey:@""];
    }
}

/// Gets the signature algorithm OID string from the certificate.
- (NSString *)sigAlgOID {
    ASN1Object * subASN1Object = [_block1 sub:2];
    if (subASN1Object) {
        ASN1Object * subASN1Obj = [subASN1Object sub:0];
        if (subASN1Obj) {
            NSString * result = [subASN1Obj value];
            return result;
        }
    }
    return nil;
}

/// Gets the DER-encoded signature algorithm parameters from this certificate's signature algorithm.
- (NSData *)sigAlgParams {
    return nil;
}

/**
 Gets a boolean array representing bits of the KeyUsage extension, (OID = 2.5.29.15).
 ```
 KeyUsage ::= BIT STRING {
 digitalSignature        (0),
 nonRepudiation          (1),
 keyEncipherment         (2),
 dataEncipherment        (3),
 keyAgreement            (4),
 keyCertSign             (5),
 cRLSign                 (6),
 encipherOnly            (7),
 decipherOnly            (8)
 }
 ```
 */
- (NSArray<NSNumber *> *)keyUsage {
    NSMutableArray<NSNumber *> * result = [NSMutableArray array];
    ASN1Object * oidBlock = [_block1 findOid:OID_KeyUsage];
    if (oidBlock) {
        ASN1Object *parent = [oidBlock parent];
        if (parent) {
            NSArray<ASN1Object *> * subASN1Object = [parent sub];
            if (subASN1Object) {
                ASN1Object * lastObject = [[subASN1Object lastObject] sub:0];
                if (lastObject) {
                    NSData * data = [lastObject value];
                    const char *bytes = [data bytes];
                    UInt8 bits = bytes[0];
                    for (int i = 0; i<= 7; i++) {
                        BOOL value = (bits & ((UInt8)1 << i)) != 0;
                        
                        [result insertObject:[NSNumber numberWithBool:value] atIndex:0];
                    }
                }
            }
        }
        
    }
    return result;
}

/// Gets a list of Strings representing the OBJECT IDENTIFIERs of the ExtKeyUsageSyntax field of the extended key usage extension, (OID = 2.5.29.37).
- (NSArray<NSString *> *)extendedKeyUsage {
    X509Extension * extensionObject = [self extensionObject:OID_ExtendedKeyUsage];
    if (extensionObject) {
        NSArray * result = [extensionObject valueAsStrings];
        if (result) {
            return result;
        }
    }
    return [NSArray array];
}

/// Gets a collection of subject alternative names from the SubjectAltName extension, (OID = 2.5.29.17).
- (NSArray<NSString *> *)subjectAlternativeNames {
    X509Extension * extensionObject = [self extensionObject:OID_SubjectAltName];
    if (extensionObject) {
        NSArray * result = [extensionObject valueAsStrings];
        if (result) {
            return result;
        }
    }
    return [NSArray array];
}

/// Gets a collection of issuer alternative names from the IssuerAltName extension, (OID = 2.5.29.18).
- (NSArray<NSString *> *)issuerAlternativeNames {
    X509Extension * extensionObject = [self extensionObject:OID_IssuerAltName];
    if (extensionObject) {
        NSArray * result = [extensionObject valueAsStrings];
        if (result) {
            return result;
        }
    }
    return [NSArray array];
}

/// Gets the informations of the key from this certificate.
- (PublicKey *)publicKey {
    ASN1Object* asn1Obj = [_block1 subscript:publicKey];
    if (asn1Obj) {
        return [[PublicKey alloc] initWithPkBlock:asn1Obj];
    }
    return nil;
}

/// Get a list of critical extension OID codes
- (NSArray<NSString *> *)criticalExtensionOIDs {
    NSArray<ASN1Object *> * extensionBlock = self.extensionBlocks;
    if (extensionBlock) {
        NSArray<NSString *> * result = [extensionBlock map:^id(id obj) {
            return [[X509Extension alloc] initWithBlock:obj];
        }];
        result = [result filter:^BOOL(id obj) {
            return [obj isCritical];
        }];
        result = [result compactMap:^id(id obj) {
            return [obj oid];
        }];
        return result;
    }
    return [NSArray array];
}

/// Get a list of non critical extension OID codes
- (NSArray<NSString *> *)nonCriticalExtensionOIDs {
    NSArray<ASN1Object *> * extensionBlock = self.extensionBlocks;
    if (extensionBlock) {
        NSArray<NSString *> * result = [extensionBlock map:^id(id obj) {
            return [[X509Extension alloc] initWithBlock:obj];
        }];
        result = [result filter:^BOOL(id obj) {
            return (![obj isCritical]);
        }];
        result = [result compactMap:^id(id obj) {
            return [obj oid];
        }];
        return result;
    }
    return [NSArray array];
}

- (NSArray<ASN1Object *> *)extensionBlocks {
    ASN1Object * asn1Object = [_block1 subscript:extensions];
    if (asn1Object) {
        ASN1Object * asn1Obj = [asn1Object sub:0];
        if (asn1Obj) {
            return [asn1Obj sub];
        }
    }
    return nil;
}

/// Gets the extension information of the given OID code.
- (X509Extension *)extensionObject:(NSString *)oid {
    ASN1Object * asn1Object = [_block1 subscript:extensions];
    if (asn1Object) {
        ASN1Object * asn1Obj = [asn1Object findOid:oid];
        if (asn1Obj) {
            ASN1Object * parent = [asn1Obj parent];
            if (parent) {
                return [[X509Extension alloc] initWithBlock:parent];
            }
        }
    }
    return nil;
}
// Format subject/issuer information in RFC1779
- (NSString *)blockDistinguishedName:(ASN1Object *)block {
    NSString *result = @"";
    NSArray *oidNames = @[
        @[@"2.5.4.3",  @"CN"],           // commonName
        @[@"2.5.4.46", @"DNQ"],          // dnQualifier
        @[@"2.5.4.5",  @"SERIALNUMBER"], // serialNumber
        @[@"2.5.4.42", @"GIVENNAME"],    // givenName
        @[@"2.5.4.4",  @"SURNAME"],      // surname
        @[@"2.5.4.11", @"OU"],           // organizationalUnitName
        @[@"2.5.4.10", @"O"],            // organizationName
        @[@"2.5.4.9",  @"STREET"],       // streetAddress
        @[@"2.5.4.7",  @"L"],            // localityName
        @[@"2.5.4.8",  @"ST"],           // stateOrProvinceName
        @[@"2.5.4.6",  @"C"],            // countryName
        @[@"1.2.840.113549.1.9.1", @"E"] // e-mail
    ];
    for (NSArray *oidName in oidNames) {
        ASN1Object *oidBlock = [block findOid:oidName[0]];
        if (oidBlock) {
            if (result.length > 0) {
                result = [result stringByAppendingFormat:@", "];
            }
            result = [result stringByAppendingFormat:@"%@", oidName[1]];
            result = [result stringByAppendingFormat:@"="];
            ASN1Object * parent = [oidBlock parent];
            if (parent) {
                NSArray<ASN1Object *> * subObjects = [parent sub];
                if (subObjects) {
                    NSString *value = [subObjects lastObject].value;
                    if (value) {
                        NSString *specialChar = @",+=\n<>#;\\";
                        NSCharacterSet *specialCharacterSet = [NSCharacterSet characterSetWithCharactersInString:specialChar];
                        
                        NSString *quote = ([value rangeOfCharacterFromSet:specialCharacterSet].location != NSNotFound) ? @"\"" : @"";
                        result = [result stringByAppendingFormat:@"%@", quote];
                        result = [result stringByAppendingFormat:@"%@", value];
                        result = [result stringByAppendingFormat:@"%@", quote];
                    }
                }
            }
            
        }
    }
    return result;
}


// read possibile PEM encoding
- (NSData *)decodeToDER:(NSData *)pemData {
    NSString * pem = [[NSString alloc] initWithData:pemData encoding:NSASCIIStringEncoding];
    if (pem && [pem containsString:beginPemBlock]) {
        NSArray *lines = [pem componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        NSString * base64buffer = @"";
        BOOL certLine = false;
        for (NSString * line in lines) {
            if ([line isEqualToString:endPemBlock]) {
                certLine = false;
            }
            if (certLine) {
                base64buffer = [base64buffer stringByAppendingString:line];
            }
            if ([line isEqualToString:beginPemBlock]) {
                certLine = true;
            }
        }
        NSData * derDataDecoded = [[NSData alloc] initWithBase64EncodedString:base64buffer options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (derDataDecoded) {
            return derDataDecoded;
        }
    }
    return nil;
}

+ (id)firstLeafValue:(ASN1Object *)block {
    ASN1Object *sub = [block sub:0];
    if (sub) {
        return [self firstLeafValue:sub];
    }
    return [block value];
}

@end



@implementation X509Extension

- (instancetype)initWithBlock:(ASN1Object *)block {
    self = [super init];
    if (self) {
        self->block = block;
    }
    return self;
}

- (NSString *)oid {
    ASN1Object * subASN1Obj = [block sub:0];
    if (subASN1Obj) {
        return subASN1Obj.value;
    }
    return nil;
}

- (NSString *)name {
    if (self.oid) {
        return [[ASN1Object oidDecodeMap] objectForKey:self.oid];
    } else {
        return [[ASN1Object oidDecodeMap] objectForKey:@""];
    }
}

- (BOOL)isCritical {
    if (block.sub.count > 2) {
        ASN1Object * subASN1Obj = [block sub:1];
        if (subASN1Obj) {
            return subASN1Obj.value;
        }
    }
    return false;
}

- (id)value {
    ASN1Object *valueBlock = [block.sub lastObject];
    if (valueBlock) {
        return [X509Certificate firstLeafValue:valueBlock];
    }
    return nil;
}

- (ASN1Object *)valueAsBlock {
    return [block.sub lastObject];
}

- (NSArray<NSString *> *)valueAsStrings {
    NSMutableArray *result = [NSMutableArray array];
    for (ASN1Object *item in [[block.sub lastObject].sub lastObject].sub) {
        NSString *name = [item value];
        if (name) {
            [result addObject:name];
        }
    }
    return result;
}

@end
