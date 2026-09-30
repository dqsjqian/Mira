#import <UIKit/UIKit.h>
#include <cstdio>
#include <cstdlib>

extern "C" int mira_device_smoke();

@interface MiraSmokeDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation MiraSmokeDelegate
- (BOOL)application:(UIApplication*)application
    didFinishLaunchingWithOptions:(NSDictionary*)options {
    static_cast<void>(application);
    static_cast<void>(options);
    return YES;
}
@end

@interface MiraSmokeSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow* window;
@end

@implementation MiraSmokeSceneDelegate
- (void)scene:(UIScene*)scene willConnectToSession:(UISceneSession*)session
    options:(UISceneConnectionOptions*)options {
    static_cast<void>(session);
    static_cast<void>(options);
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    self.window = [[UIWindow alloc] initWithWindowScene:static_cast<UIWindowScene*>(scene)];
    UIViewController* controller = [[UIViewController alloc] init];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel* label = [[UILabel alloc] initWithFrame:controller.view.bounds];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = @"Mira loopback smoke is running";
    [controller.view addSubview:label];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 25 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        std::fprintf(stderr, "MIRA_SMOKE_WATCHDOG FAIL\n");
        std::fflush(nullptr);
        std::_Exit(124);
    });
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        const int result = mira_device_smoke();
        std::fflush(nullptr);
        std::exit(result);
    });
}
@end

int main(int argc, char** argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(MiraSmokeDelegate.class));
    }
}
