//
//  NSData+IntValue.m
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import "NSData+IntValue.h"

@implementation NSData (IntValue)

- (NSNumber*)toIntValue {
    if (self.length > 8) { // check if suitable for UInt64
        return nil;
    }
    
    UInt64 value = 0;
    const char *bytes = [self bytes];

    for (int i = 0; i < self.length; i++) {
        UInt8 byte = bytes[i];
        UInt64 v = (UInt64)byte << ( (UInt64) (8*(self.length-i-1)) );
        value += v;
    }
    return [NSNumber numberWithLongLong:value];
}

@end
