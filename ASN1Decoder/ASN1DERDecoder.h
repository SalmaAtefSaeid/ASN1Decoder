//
//  ASN1DERDecoder.h
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Object.h"

@interface ASN1DERDecoder : NSObject

+ (NSArray<ASN1Object*>*)decode:(NSData*)data error:(NSError * __autoreleasing *)error;

@end

