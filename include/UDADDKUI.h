//
//  udaddkui.h
//  udaddkui
//
//  Created by Dono Harjanto on 9/22/14.
//  Copyright (c) 2014 DeviceAuthority. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#define WAIT_TIME_INFINITE (-1)ull
#define WAIT_TIME_DEFAULT (10 * NSEC_PER_MSEC)

#define PIN_MODE_NUMBER 0
#define PIN_MODE_MIXED 1

#define WAIT_FOR_ACTION_SUCCESS 0
#define WAIT_FOR_ACTION_CANCELED -1
#define WAIT_FOR_ACTION_TIMEDOUT -2

typedef void (^UDADDKUIHandler)(NSString *actionResult);

@interface UDADDKUI : NSObject <UIAlertViewDelegate>

+(void)waitForPin:(int)mode withTitle:(NSString *)title handler:(UDADDKUIHandler)handler;
+(void)waitForAction:(int)waitTimeInMillis handler:(UDADDKUIHandler)handler;

@end