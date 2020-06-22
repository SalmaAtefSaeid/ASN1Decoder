//
//  ASN1DERDecoder.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "ASN1DERDecoder.h"
#import "ASN1Identifier.h"
#import "NSData+IntValue.h"


@interface DataIterator : NSObject



+(DataIterator*) makeIteratorFromData:(NSData*) data;
-(NSNumber*) next;

@end


@interface DataIterator()

@property (nonatomic, strong) NSData* data;
@property (nonatomic, assign) int index;

@end

@implementation DataIterator

+(DataIterator*) makeIteratorFromData:(NSData*) data{
    
    DataIterator* itertor = [DataIterator new];
    itertor.data = data;
    itertor.index = 0;
    return itertor;
}

-(NSNumber*) next{
    if ( (self.index >= 0) && (self.index < self.data.length) ){
        const char * bytes = [self.data bytes];
        int i = self.index;
        self.index++;
        return [NSNumber numberWithUnsignedChar:bytes[i]];
    }
    return nil;
}
@end



@implementation ASN1DERDecoder

+ (NSArray<ASN1Object*>*)decode:(NSData*)data error:(NSError * __autoreleasing *)error {
    DataIterator * iterator = [DataIterator makeIteratorFromData:data];
    return [self parse:iterator error:error];
}

+ (NSArray<ASN1Object*>*)parse:(DataIterator*)iterator error:(NSError * __autoreleasing *)error {
    NSMutableArray<ASN1Object*>* result = [NSMutableArray array];
    
    for (NSNumber *next = [iterator next]; next != nil; next = [iterator next]) {
        UInt8 nextValue = [next unsignedCharValue];
        ASN1Object * asn1obj = [ASN1Object new];
        asn1obj.identifier = [[ASN1Identifier alloc] initWithRawValue:nextValue];
        if ([asn1obj.identifier isConstructed]) {

            NSData * contentData = [self loadSubContent:iterator error:error];

            if ([contentData length] == 0) {
                asn1obj.sub = [self parse:iterator error:error];
            } else {
                DataIterator * subIterator = [DataIterator makeIteratorFromData:contentData];
                asn1obj.sub = [self parse:subIterator error:error];
            }
            asn1obj.value = nil;
            asn1obj.rawValue = [[NSData alloc] initWithData:contentData];
            for (ASN1Object * item in asn1obj.sub) {
                item.parent = asn1obj;
            }
        } else {
            if ([asn1obj.identifier typeClass] == universal) {
                
                NSData * contentData = [self loadSubContent:iterator error:error];
                
                asn1obj.rawValue = [[NSData alloc] initWithData:contentData];
                
                // decode the content data with come more convenient format
                switch ([asn1obj.identifier tagNumber]) {
                    case endOfContent:
                        return result;
                        break;
                    case boolean: {
                        const char *bytes = [contentData bytes];
                        if (bytes) {
                            UInt8 value = bytes[0];
                            asn1obj.value = [NSNumber numberWithInteger:value > 0 ? true : false];
                        }
                    }
                        break;
                    case integerEnum: {
                        const char *bytes = [contentData bytes];
                        while (bytes != nil && bytes[0] == 0) {
                            contentData = [contentData subdataWithRange:NSMakeRange(1, contentData.length-1)];
                            bytes = [contentData bytes];
                        }
                        asn1obj.value = contentData;
                    }
                        break;
                    case null:
                        asn1obj.value = nil;
                        break;
                    case objectIdentifierEnum:
                        asn1obj.value = [self decodeOid:&contentData];
                        break;
                    case utf8String:
                    case printableString:
                    case numericString:
                    case generalString:
                    case universalString:
                    case characterString:
                    case t61String:
                        asn1obj.value = [[NSString alloc] initWithData:contentData encoding:NSUTF8StringEncoding];
                        break;
                    case bmpString:
                        asn1obj.value = [[NSString alloc] initWithData:contentData encoding:NSUnicodeStringEncoding];
                        break;
                    case visibleString:
                    case ia5String:
                        asn1obj.value = [[NSString alloc] initWithData:contentData encoding:NSASCIIStringEncoding];
                        break;
                    case utcTime:
                        asn1obj.value = [self dateFormatter:contentData formats:@[@"yyMMddHHmmssZ", @"yyMMddHHmmZ"]];
                        break;
                    case generalizedTime:
                        asn1obj.value = [self dateFormatter:contentData formats:@[@"yyyyMMddHHmmssZ"]];
                        break;
                    case bitString:
                        if ([contentData length] > 0) {
                            contentData = [contentData subdataWithRange:NSMakeRange(1, contentData.length-1)];
                        }
                        asn1obj.value = contentData;
                        break;
                    case octetString:{
                        NSError * error2;
                        DataIterator * subIterator = [DataIterator makeIteratorFromData:contentData];
                        NSArray<ASN1Object *> * resultArray = [self parse:subIterator error:&error2];
                        if (!error2) {
                            asn1obj.sub = resultArray;
                        } else {
                            NSString *str = [[NSString alloc] initWithData:contentData encoding:NSUTF8StringEncoding];
                            if (str) {
                                asn1obj.value = str;
                            } else {
                                asn1obj.value = contentData;
                            }
                        }
                    }
                        break;
                    default:
                        //                        NSLog(@"unsupported tag: %lu", (unsigned long)[asn1obj.identifier tagNumber]);
                        asn1obj.value = contentData;
                        break;
                }
            } else {
                // custom/private tag

                NSData * contentData = [self loadSubContent:iterator error:error];

                NSString * str = [[NSString alloc] initWithData:contentData encoding:NSUTF8StringEncoding];
                if (str) {
                    asn1obj.value = str;
                } else {
                    asn1obj.value = contentData;
                }
            }
        }
        [result addObject:asn1obj];
    }
    return result;
}

// Decode the number of bytes of the content
+ (UInt64)getContentLength:(DataIterator*)iterator {
    NSNumber* first = [iterator next];
    if (first == nil) { return 0; }

    UInt8 firstValue = [first unsignedCharValue];

    if (((firstValue) & 0x80) != 0) { // long
        UInt8 octetsToRead = (firstValue) - 0x80;
        NSMutableData * data = [NSMutableData new];

        // TODO: refactor to remove loop
        for (int i = 0; i < octetsToRead; i++) {
            NSNumber* n = [iterator next];
            if (n != nil) {
                [data appendBytes:(UInt8 []){[n unsignedCharValue]} length:1];
            }
        }
        
        NSNumber* intValue = [data toIntValue];
        return (intValue != nil) ? [intValue unsignedLongLongValue] : 0 ;
        
    } else {

        return (UInt64)[first unsignedCharValue];
    }
}

+ (NSData*)loadSubContent:(DataIterator*)iterator error:(NSError * __autoreleasing *)error {
    
    UInt64 len = [self getContentLength:iterator];
    
    if (len >= NSIntegerMax) {
        return [NSData new];
    }
    
    NSMutableData *byteArray = [NSMutableData new];
    
    for (int i = 0; i < (int)len; i++) {
        NSNumber* n = [iterator next];
        if (n != nil) {
            [byteArray appendBytes:(UInt8 []){[n unsignedCharValue]} length:1];
        }else {
            *error = [[NSError alloc] initWithDomain:@"outOfBuffer" code:1 userInfo:nil];
        }
    }

    return byteArray;
}

// Decode DER OID bytes to String with dot notation
+ (NSString*)decodeOid:(NSData**)contentData {
    NSData *data = [[NSData alloc] initWithData:*contentData];
    if ([*contentData length] == 0) {
        return @"";
    }
    NSString * oid = @"";
    UInt8 first = ((const char *)[data bytes])[0];
    data = [data subdataWithRange:NSMakeRange(1, data.length-1)];
    oid = [oid stringByAppendingFormat:@"%d.%d", first/40, first%40];
    int t = 0;
    while ([data length] > 0) {
        int n = (int)((const char *)[data bytes])[0];
        data = [data subdataWithRange:NSMakeRange(1, data.length-1)];
        t = (t << 7) | (n & 0x7F);
        if ((n & 0x80) == 0) {
            oid = [oid stringByAppendingFormat:@".%d", t];
            t = 0;
        }
    }
    *contentData = data;
    return oid;
}

+ (NSDate*)dateFormatter:(NSData *)contentData formats:(NSArray<NSString*>*)formats {
    NSString * str = [[NSString alloc] initWithData:contentData encoding:NSUTF8StringEncoding];
    if (str) {
        for (NSString * format in formats) {
            NSDateFormatter *fmt = [NSDateFormatter new];
            fmt.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
            fmt.dateFormat = format;
            NSDate * dt = [fmt dateFromString:str];
            if (dt) {
                return dt;
            }
        }
    }
    return nil;
}
//enum ASN1Error: Error {
//    case parseError
//    case outOfBuffer
//}


@end
