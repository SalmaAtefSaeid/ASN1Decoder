//
//  PublicKey.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "PublicKey.h"
#import "ASN1DERDecoder.h"

NSString* const OID_ECPublicKey   = @"1.2.840.10045.2.1";
NSString* const OID_RSAEncryption = @"1.2.840.113549.1.1.1";

@interface PublicKey() {
    ASN1Object *pkBlock;
}

@property (readonly, strong) NSString* algOid;
@property (readonly, strong) NSString* algName;
@property (readonly, strong) NSString* algParams;

@end


@implementation PublicKey

- (instancetype)initWithPkBlock:(ASN1Object *)pkBlock {
    self = [super init];
    if (self) {
        self->pkBlock = pkBlock;
    }
    return self;
}

- (NSString *)algOid {
    return [[pkBlock sub:0] sub:0].value;
}

- (NSString *)algName {
    if (self.algOid) {
        return [[ASN1Object oidDecodeMap] objectForKey:self.algOid];
    } else {
        return [[ASN1Object oidDecodeMap] objectForKey:@""];
    }
}

- (NSString *)algParams {
    return [[pkBlock sub:0] sub:1].value;
}

- (NSData *)key {
    NSData * keyData = [pkBlock sub:1].value;
    if ((!self.algOid) && (!keyData)) {
        return nil;
    }
    if ([self.algOid isEqualToString:OID_ECPublicKey]) {
        return keyData;
    } else if ([self.algOid isEqualToString:OID_RSAEncryption]) {
        NSError *error;
        NSArray<ASN1Object*> *publicKeyAsn1Objects = [ASN1DERDecoder decode:keyData error:&error];
        if (error != nil) {
            return nil;
        }
        NSData * publicKeyModulus = [[publicKeyAsn1Objects firstObject] sub:0].value;
        if (!publicKeyModulus) {
            return nil;
        }
        return publicKeyModulus;
    } else {
        return nil;
    }
}


@end

