//
//  PublicKey.h
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Object.h"

@interface PublicKey : NSObject

@property (readonly, strong) NSData* key;

- (instancetype)initWithPkBlock:(ASN1Object *)pkBlock;

@end
