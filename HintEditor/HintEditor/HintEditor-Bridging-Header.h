//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

#import <Cocoa/Cocoa.h>

@interface NSTextView (Placeholder)

@property (nonatomic, retain) NSString *placeholderString;

@end

@implementation NSTextView (Placeholder)

@dynamic placeholderString;

@end
