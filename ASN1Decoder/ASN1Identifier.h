//
//  ASN1Identifier.h
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum ClassEnum : NSUInteger {
    universal       = 0x00,
    application     = 0x40,
    contextSpecific = 0x80,
    privateEnum     = 0xC0
} ClassEnum;

typedef enum TagNumber : NSUInteger {
    endOfContent         = 0x00,
    boolean              = 0x01,
    integerEnum          = 0x02,
    bitString            = 0x03,
    octetString          = 0x04,
    null                 = 0x05,
    objectIdentifierEnum = 0x06,
    objectDescriptor     = 0x07,
    external             = 0x08,
    readEnum             = 0x09,
    enumerated           = 0x0A,
    embeddedPdv          = 0x0B,
    utf8String           = 0x0C,
    relativeOid          = 0x0D,
    sequenceEnum         = 0x10,
    set                  = 0x11,
    numericString        = 0x12,
    printableString      = 0x13,
    t61String            = 0x14,
    videotexString       = 0x15,
    ia5String            = 0x16,
    utcTime              = 0x17,
    generalizedTime      = 0x18,
    graphicString        = 0x19,
    visibleString        = 0x1A,
    generalString        = 0x1B,
    universalString      = 0x1C,
    characterString      = 0x1D,
    bmpString            = 0x1E
} TagNumber;

@interface ASN1Identifier : NSObject

@property (nonatomic, assign) UInt8 rawValue;

- (instancetype)initWithRawValue:(UInt8)rawValue;
- (BOOL)isConstructed;
- (TagNumber)tagNumber;
- (ClassEnum)typeClass;

@end
