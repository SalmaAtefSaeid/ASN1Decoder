//
//  X509Certificate.h
//  TWISDK
//
//  Created by salma atef on 6/22/20.
//  Copyright © 2020 salma atef. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASN1Object.h"
#import "PublicKey.h"

@interface X509Certificate : NSObject

@property (readonly, strong) NSData* signature;
@property (nonatomic, strong) ASN1Object* block1;
@property (readonly, strong) PublicKey* publicKey;
@property (readonly, strong) NSString* subjectDistinguishedName;

- (void)populateCert:(NSData *)data error:(NSError * __autoreleasing *)error;

@end

@interface X509Extension : NSObject {
    ASN1Object *block;
}

- (instancetype)initWithBlock:(ASN1Object *)block;

@property (readonly, strong) NSString* oid;
@property (readonly, strong) NSString* name;
@property (readonly, assign) BOOL isCritical;
@property (readonly, strong) id value;
@property (readonly, strong) ASN1Object* valueAsBlock;
@property (readonly, strong) NSArray<NSString*>* valueAsStrings;

@end
