//
//  /mavericks/UDADDK/UDADDK.h
//  LibUDADDK
//
//  Created by Dono Harjanto on 4/21/12.
//  Copyright 2014 DeviceAuthority Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface UDADDK : NSObject {
    
}

+(NSString*)getDeviceKeyVersion;
+(NSString*)getDeviceKey:(boolean_t)fipsEnabled;
+(NSString*)getDeviceKeyWithChallenge:(NSString*)challenge;
+(NSString*)getDeviceKeyWithChallenge:(NSString*)challenge fipsEnabled:(boolean_t)fipsEnabled;
+(NSString*)getDeviceKeyWithChallenge:(NSString*)challenge withTransactionValue:(NSString*)transactionValue;
+(NSString*)getDeviceKeyWithChallenge:(NSString*)challenge withMetaData:(NSDictionary*)metaDataDict fipsEnabled:(boolean_t)fipsEnabled;
+(NSString*)getDeviceKeyWithChallenge:(NSString*)challenge withTransactionValue:(NSString*)transactionValue fipsEnabled:(boolean_t)fipsEnabled;
+(NSString*)getDeviceTid;
+(NSString*)getLogBuffer;

@end
