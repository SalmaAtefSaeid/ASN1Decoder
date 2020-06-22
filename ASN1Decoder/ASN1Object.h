//
//  ASN1Object.h
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Identifier.h"

@interface ASN1Object : NSObject

@property (nonatomic, strong) id value;
@property (nonatomic, strong) NSArray<ASN1Object *> * sub;
@property (nonatomic, weak) ASN1Object * parent;
@property (nonatomic, strong) ASN1Identifier * identifier;
@property (nonatomic, strong) NSData * rawValue;
@property (readonly, class, strong) NSDictionary<NSString *, NSString *>* oidDecodeMap;

- (ASN1Object *)sub:(int)index;
- (ASN1Object *)findOid:(NSString *)oid;
- (int)subCount;

@end
