//
//  ASN1Identifier.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "ASN1Identifier.h"

@implementation ASN1Identifier

- (instancetype)initWithRawValue:(UInt8)rawValue {
    self = [super init];
    if (self) {
        self.rawValue = rawValue;
    }
    return self;
}

- (ClassEnum)typeClass {
    NSArray * array = [[NSArray alloc] initWithObjects:[[NSNumber alloc] initWithUnsignedInt:application], [[NSNumber alloc] initWithUnsignedInt:contextSpecific], [[NSNumber alloc] initWithUnsignedInt:privateEnum], nil];
    
    for (NSNumber *tc in array) {
        if ((self.rawValue & [tc unsignedCharValue]) == [tc unsignedCharValue]) {
            return [tc unsignedIntValue];
        }
    }
    return universal;
}

- (BOOL)isPrimitive {
    return (self.rawValue & 0x20) == 0;
}

- (BOOL)isConstructed {
    return (self.rawValue & 0x20) != 0;
}

- (TagNumber)tagNumber {
    
    UInt8 array[] = {
    endOfContent,
    boolean,
    integerEnum,
    bitString,
    octetString,
    null,
    objectIdentifierEnum,
    objectDescriptor,
    external,
    readEnum,
    enumerated,
    embeddedPdv,
    utf8String,
    relativeOid,
    sequenceEnum,
    set,
    numericString,
    printableString,
    t61String,
    videotexString,
    ia5String,
    utcTime,
    generalizedTime,
    graphicString,
    visibleString,
    generalString,
    universalString,
    characterString,
    bmpString,
};
    UInt8 targetValue = self.rawValue & 0x1F;
    
    for (int i=0; i<sizeof(array); i++){
        if (array[i] == targetValue){
            return (TagNumber)targetValue;
        }
    }
    return endOfContent;
}


- (NSString *)description {
    
    if ([self typeClass] == universal) {
        return [NSString stringWithFormat:@"%lu", (unsigned long)[self tagNumber]];
    } else {
        return [NSString stringWithFormat:@"%lu(%lu)", (unsigned long)[self typeClass], (unsigned long)[self tagNumber]];
    }
}

@end
