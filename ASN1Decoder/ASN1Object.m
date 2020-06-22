//
//  ASN1Object.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "ASN1Object.h"

@implementation ASN1Object

- (ASN1Object *)sub:(int)index {
    if (self.sub && index >= 0 && index < self.sub.count) {
        return self.sub[index];
    }
    return nil;
}

- (int)subCount {
    int result = (int)self.sub.count;
    return result;
}

- (ASN1Object *)findOid:(NSString *)oid {
    NSArray *array = self.sub;
    if (array == nil) {
        array = [NSArray array];
    }
    for (ASN1Object *child in array) {
        if ([child.identifier tagNumber] == objectIdentifierEnum) {
            NSString * childValue = child.value;
            if ([childValue isEqualToString:oid]) {
                return child;
            }
        } else {
            ASN1Object * result = [child findOid:oid];
            if (result) {
                return result;
            }
        }
    }
    return nil;
}

- (NSString *)printAsn1:(NSString *)insets {
    NSString * output = @"";
    if (insets) {
        output = insets;
    }
    NSString * description = [[self.identifier description] uppercaseString];
    if (description) {
        output = [output stringByAppendingString:description];
    } else {
        output = [output stringByAppendingString:@""];
    }
    if (self.value != nil) {
        output = [output stringByAppendingFormat:@" : %@", self.value];
    } else {
        output = [output stringByAppendingString:@""];
    }
    if (([self.identifier typeClass] == universal) && ([self.identifier tagNumber] == objectIdentifierEnum)) {
        NSString * descr;
        if ((NSString*)self.value) {
            descr = [[ASN1Object oidDecodeMap] objectForKey:(NSString*)self.value];
        } else {
            descr = [[ASN1Object oidDecodeMap] objectForKey:@""];
        }
        if (descr) {
            output = [output stringByAppendingFormat:@" (%@)", descr];
        }
    }
    NSString * s = ((self.sub != nil) && (self.sub.count > 0)) ? @" {" : @"";
    output = [output stringByAppendingString:s];
    output = [output stringByAppendingString:@"\n"];
    NSArray * array = self.sub;
    if (!array) {
        array = [NSArray array];
    }
    for (ASN1Object *item in array) {
        NSString * insetsString = [[NSString alloc] initWithFormat:@"%@    ", insets];
        output = [output stringByAppendingString:[item printAsn1:insetsString]];
    }
    NSString * str = self.sub != nil && self.sub.count > 0 ? [[NSString alloc] initWithFormat:@"%@}\n", insets] : @"";
    output = [output stringByAppendingString:str];
    return output;
}

+ (NSDictionary<NSString *,NSString *> *)oidDecodeMap {
    return @{
        @"0.4.0.1862.1.1"             : @"etsiQcsCompliance",
        @"0.4.0.1862.1.3"             : @"etsiQcsRetentionPeriod",
        @"0.4.0.1862.1.4"             : @"etsiQcsQcSSCD",
        @"1.2.840.10040.4.1"          : @"dsa",
        @"1.2.840.10045.2.1"          : @"ecPublicKey",
        @"1.2.840.10045.3.1.7"        : @"prime256v1",
        @"1.2.840.10045.4.3.2"        : @"ecdsaWithSHA256",
        @"1.2.840.10045.4.3.4"        : @"ecdsaWithSHA512",
        @"1.2.840.113549.1.1.1"       : @"rsaEncryption",
        @"1.2.840.113549.1.1.4"       : @"md5WithRSAEncryption",
        @"1.2.840.113549.1.1.5"       : @"sha1WithRSAEncryption",
        @"1.2.840.113549.1.1.11"      : @"sha256WithRSAEncryption",
        @"1.2.840.113549.1.7.1"       : @"data",
        @"1.2.840.113549.1.7.2"       : @"signedData",
        @"1.2.840.113549.1.9.1"       : @"emailAddress",
        @"1.2.840.113549.1.9.16.2.47" : @"signingCertificateV2",
        @"1.2.840.113549.1.9.3"       : @"contentType",
        @"1.2.840.113549.1.9.4"       : @"messageDigest",
        @"1.2.840.113549.1.9.5"       : @"signingTime",
        @"1.3.6.1.4.1.11129.2.4.2"    : @"certificateExtension",
        @"1.3.6.1.4.1.311.60.2.1.2"   : @"jurisdictionOfIncorporationSP",
        @"1.3.6.1.4.1.311.60.2.1.3"   : @"jurisdictionOfIncorporationC",
        @"1.3.6.1.5.5.7.1.1"          : @"authorityInfoAccess",
        @"1.3.6.1.5.5.7.1.3"          : @"qcStatements",
        @"1.3.6.1.5.5.7.2.1"          : @"cps",
        @"1.3.6.1.5.5.7.2.2"          : @"unotice",
        @"1.3.6.1.5.5.7.3.1"          : @"serverAuth",
        @"1.3.6.1.5.5.7.3.2"          : @"clientAuth",
        @"1.3.6.1.5.5.7.48.1"         : @"ocsp",
        @"1.3.6.1.5.5.7.48.2"         : @"caIssuers",
        @"1.3.6.1.5.5.7.9.1"          : @"dateOfBirth",
        @"2.16.840.1.101.3.4.2.1"     : @"sha-256",
        @"2.16.840.1.113733.1.7.23.6" : @"VeriSign EV policy",
        @"2.23.140.1.1"               : @"extendedValidation",
        @"2.23.140.1.2.2"             : @"extendedValidation",
        @"2.5.29.14"                  : @"subjectKeyIdentifier",
        @"2.5.29.15"                  : @"keyUsage",
        @"2.5.29.17"                  : @"subjectAltName",
        @"2.5.29.18"                  : @"issuerAltName",
        @"2.5.29.19"                  : @"basicConstraints",
        @"2.5.29.31"                  : @"cRLDistributionPoints",
        @"2.5.29.32"                  : @"certificatePolicies",
        @"2.5.29.35"                  : @"authorityKeyIdentifier",
        @"2.5.29.37"                  : @"extKeyUsage",
        @"2.5.29.9"                   : @"subjectDirectoryAttributes",
        @"2.5.4.10"                   : @"organizationName",
        @"2.5.4.11"                   : @"organizationalUnitName",
        @"2.5.4.15"                   : @"businessCategory",
        @"2.5.4.17"                   : @"postalCode",
        @"2.5.4.3"                    : @"commonName",
        @"2.5.4.4"                    : @"surname",
        @"2.5.4.42"                   : @"givenName",
        @"2.5.4.46"                   : @"dnQualifier",
        @"2.5.4.5"                    : @"serialNumber",
        @"2.5.4.6"                    : @"countryName",
        @"2.5.4.7"                    : @"localityName",
        @"2.5.4.8"                    : @"stateOrProvinceName",
        @"2.5.4.9"                    : @"streetAddress"
    };
}

@end
