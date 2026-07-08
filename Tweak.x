#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import <UIKit/UIKit.h>
#import <MapKit/MapKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Security/Security.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <unistd.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#include <errno.h>

#define WOLFOX_TOOL_NAME @"Gps Wolfox"

#ifdef __cplusplus
extern "C" {
#endif
intptr_t _dyld_get_image_slide(uint32_t image_index);
#ifdef __cplusplus
}
#endif

// -------------- Fishhook & Rebinding --------------
#ifndef FISHHOOK_H
#define FISHHOOK_H
struct rebinding { const char *name; void *replacement; void **replaced; };
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);
#endif

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

struct rebindings_entry { struct rebinding *rebindings; size_t rebindings_nel; struct rebindings_entry *next; };
static struct rebindings_entry *_rebindings_head = NULL;

static int prepend_rebindings(struct rebindings_entry **head, struct rebinding rebindings[], size_t rebindings_nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) return -1;
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * rebindings_nel);
  if (!new_entry->rebindings) { free(new_entry); return -1; }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * rebindings_nel);
  new_entry->rebindings_nel = rebindings_nel;
  new_entry->next = *head;
  *head = new_entry;
  return 0;
}

static void rebind_symbols_sec(struct rebindings_entry *rebindings, section_t *section, intptr_t slide, nlist_t *symtab, char *strtab, uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **astruct = (void **)((uintptr_t)section->addr + slide);
  for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL || symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_has_leading_underscore = symbol_name[0] == '_';
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (size_t j = 0; j < cur->rebindings_nel; j++) {
        char *rebind_name = (char *)cur->rebindings[j].name;
        if (symbol_has_leading_underscore && strlen(symbol_name) > 1 && strcmp(&symbol_name[1], rebind_name) == 0) {
          if (cur->rebindings[j].replaced != NULL && *cur->rebindings[j].replaced != astruct[i]) *cur->rebindings[j].replaced = astruct[i];
          vm_protect(mach_task_self(), (vm_address_t)&astruct[i], sizeof(void *), FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
          astruct[i] = cur->rebindings[j].replacement;
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

static void rebind_symbols_image(struct rebindings_entry *rebindings, const struct mach_header *header, intptr_t slide) {
  segment_command_t *linkedit_segment = NULL;
  segment_command_t *data_segment = NULL;
  segment_command_t *data_const_segment = NULL;
  struct symtab_command *symtab_cmd = NULL;
  struct dysymtab_command *dysymtab_cmd = NULL;
  
  segment_command_t *cur_seg_cmd;
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) linkedit_segment = cur_seg_cmd;
      else if (strcmp(cur_seg_cmd->segname, SEG_DATA) == 0) data_segment = cur_seg_cmd;
      else if (strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) == 0) data_const_segment = cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) symtab_cmd = (struct symtab_command *)cur_seg_cmd;
    else if (cur_seg_cmd->cmd == LC_DYSYMTAB) dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || (!data_segment && !data_const_segment)) return;
  uintptr_t linkedit_base = (uintptr_t)linkedit_segment->vmaddr - linkedit_segment->fileoff + slide;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  if (data_segment) {
    uintptr_t temp = (uintptr_t)data_segment + sizeof(segment_command_t);
    for (uint32_t i = 0; i < data_segment->nsects; i++, temp += sizeof(section_t)) {
      section_t *sect = (section_t *)temp;
      uint8_t type = sect->flags & SECTION_TYPE;
      if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) rebind_symbols_sec(rebindings, sect, slide, symtab, strtab, indirect_symtab);
    }
  }
  if (data_const_segment) {
    uintptr_t temp = (uintptr_t)data_const_segment + sizeof(segment_command_t);
    for (uint32_t i = 0; i < data_const_segment->nsects; i++, temp += sizeof(section_t)) {
      section_t *sect = (section_t *)temp;
      uint8_t type = sect->flags & SECTION_TYPE;
      if (type == S_LAZY_SYMBOL_POINTERS || type == S_NON_LAZY_SYMBOL_POINTERS) rebind_symbols_sec(rebindings, sect, slide, symtab, strtab, indirect_symtab);
    }
  }
}

static void _rebind_symbols_image(const struct mach_header *header, intptr_t slide) {
    rebind_symbols_image(_rebindings_head, header, slide);
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int err = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (err) return err;
  if (!_rebindings_head->next) _dyld_register_func_for_add_image(_rebind_symbols_image);
  else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) rebind_symbols_image(_rebindings_head, _dyld_get_image_header(i), _dyld_get_image_slide(i));
  }
  return 0;
}

// -------------- System Bypasses --------------
static __attribute__((always_inline)) void wolfox_safe_exit(int code) {
#ifdef __arm64__
    register int x0 __asm__("w0") = code;
    register int x16 __asm__("x16") = 1;
    __asm__ volatile ("svc #0x80" : : "r"(x0), "r"(x16) : "memory");
#else
    exit(code);
#endif
}

static int (*orig_dladdr)(const void *, Dl_info *);
static int hook_dladdr(const void *addr, Dl_info *info) {
    int res = orig_dladdr(addr, info);
    if (res && info && info->dli_fname) {
        const char *fname = info->dli_fname;
        if (strstr(fname, "Wolfox") || strstr(fname, "Spoof") || strstr(fname, "FakeGPS")) {
            info->dli_fname = "/usr/lib/libobjc.A.dylib";
        }
    }
    return res;
}

static void (*orig_exit_fn)(int);
static void hook_exit_fn(int code) { return; }

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        if (ret == 0 && oldp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *info = (struct kinfo_proc *)oldp;
            info->kp_proc.p_flag &= ~0x00000800;
        }
    }
    return ret;
}

static const char *(*orig_class_getImageName)(Class);
static const char *hook_class_getImageName(Class cls) {
    const char *name = orig_class_getImageName(cls);
    if (name) {
        if (strstr(name, "Wolfox") || strstr(name, "Spoof") || strstr(name, "FakeGPS")) return "/usr/lib/libobjc.A.dylib";
    }
    return name;
}

static void (*orig_alert_viewWillAppear)(id, SEL, BOOL);
static void hook_alert_viewWillAppear(UIAlertController *self, SEL _cmd, BOOL animated) {
    NSString *title = self.title.lowercaseString ?: @"";
    NSString *msg   = self.message.lowercaseString ?: @"";
    
    if ([title containsString:@"تم الحفظ"] || [title containsString:@"إعادة تشغيل"]) {
        orig_alert_viewWillAppear(self, _cmd, animated);
        return;
    }
    NSArray *blocked = @[@"unauthorized", @"غير مصرح", @"jailbreak", @"جيلبريك", @"معدل", @"app store", @"tamper", @"cracked", @"outside"];
    for (NSString *kw in blocked) {
        if ([title containsString:kw] || [msg containsString:kw]) {
            self.view.hidden = YES; self.view.alpha = 0.0;
            [self dismissViewControllerAnimated:NO completion:nil];
            return;
        }
    }
    orig_alert_viewWillAppear(self, _cmd, animated);
}

// -------------- Main Data Store --------------
@interface WolfoxSpoofStore : NSObject
@property (nonatomic, assign) CLLocationCoordinate2D fakeCoords;
@property (nonatomic, assign) BOOL isActive;
@property (nonatomic, assign) BOOL isJitterActive;
@property (nonatomic, assign) double jitterDistance;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *favorites;
@property (nonatomic, assign) BOOL hasStoredLocation;
@property (nonatomic, assign) double driftLatitude;
@property (nonatomic, assign) double driftLongitude;

// Route Simulation
@property (nonatomic, assign) BOOL isRouteActive;
@property (nonatomic, assign) CLLocationCoordinate2D startCoords;
@property (nonatomic, assign) CLLocationCoordinate2D endCoords;
@property (nonatomic, assign) double travelSpeed;
@property (nonatomic, assign) CLLocationCoordinate2D currentMovingCoords;

+ (instancetype)shared;
- (void)save;
- (void)load;
@end

@implementation WolfoxSpoofStore
+ (instancetype)shared {
    static WolfoxSpoofStore *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[WolfoxSpoofStore alloc] init]; });
    return s;
}
- (instancetype)init {
    if (self = [super init]) {
        _favorites = [NSMutableArray array];
        _driftLatitude = 0.0; _driftLongitude = 0.0; _jitterDistance = 10.0;
        _travelSpeed = 20.0;
        [self load];
    }
    return self;
}
- (void)save {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    [u setDouble:self.fakeCoords.latitude forKey:@"WolfoxSpoof_LAT_S"];
    [u setDouble:self.fakeCoords.longitude forKey:@"WolfoxSpoof_LON_S"];
    [u setBool:self.isActive forKey:@"WolfoxSpoof_ACTIVE_S"];
    [u setBool:self.isJitterActive forKey:@"WolfoxSpoof_JITTER_S"];
    [u setDouble:self.jitterDistance forKey:@"WolfoxSpoof_JITTER_DIST"];
    [u setObject:self.favorites forKey:@"WolfoxSpoof_FAVS_S"];
    [u setBool:self.hasStoredLocation forKey:@"WolfoxSpoof_HAS_LOC"];
    [u synchronize];
}
- (void)load {
    NSUserDefaults *u = [NSUserDefaults standardUserDefaults];
    self.isActive = [u boolForKey:@"WolfoxSpoof_ACTIVE_S"];
    self.isJitterActive = [u boolForKey:@"WolfoxSpoof_JITTER_S"];
    self.hasStoredLocation = [u boolForKey:@"WolfoxSpoof_HAS_LOC"];
    double jDist = [u doubleForKey:@"WolfoxSpoof_JITTER_DIST"];
    self.jitterDistance = jDist > 0 ? jDist : 10.0;
    NSArray *saved = [u arrayForKey:@"WolfoxSpoof_FAVS_S"];
    self.favorites = saved ? [NSMutableArray arrayWithArray:saved] : [NSMutableArray array];
    if (self.hasStoredLocation) self.fakeCoords = CLLocationCoordinate2DMake([u doubleForKey:@"WolfoxSpoof_LAT_S"], [u doubleForKey:@"WolfoxSpoof_LON_S"]);
    else self.fakeCoords = CLLocationCoordinate2DMake(24.7136, 46.6753); 
    self.currentMovingCoords = self.fakeCoords;
}
@end

// -------------- PassThrough Window --------------
@interface WolfoxSpoofPassThroughWindow : UIWindow
@end
@implementation WolfoxSpoofPassThroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hitView = [super hitTest:point withEvent:event];
    if (hitView == self || hitView == self.rootViewController.view) return nil;
    return hitView;
}
@end
static UIWindow *wolfox_overlayWindow = nil;

// -------------- Main UI & Bluetooth Scanner --------------
@interface WolfoxSpoofOverlay : UIView <MKMapViewDelegate, UISearchBarDelegate, UITableViewDelegate, UITableViewDataSource, CBCentralManagerDelegate>
@property (nonatomic, strong) UIButton *gpsBtn;
@property (nonatomic, strong) UIVisualEffectView *panel;
@property (nonatomic, strong) UIScrollView *scrollView;
@property (nonatomic, strong) UIView *controlsContainer;
@property (nonatomic, strong) MKMapView *map;
@property (nonatomic, strong) UIButton *expandMapBtn;
@property (nonatomic, strong) UISegmentedControl *mapTypeControl;
@property (nonatomic, strong) MKPointAnnotation *pin;
@property (nonatomic, strong) UISearchBar *searchBar;

// Favorites
@property (nonatomic, strong) UIVisualEffectView *favView;
@property (nonatomic, strong) UITableView *table;

// Bluetooth Scanner
@property (nonatomic, strong) UIVisualEffectView *btView;
@property (nonatomic, strong) UITableView *btTable;
@property (nonatomic, strong) UILabel *btStatusLabel;
@property (nonatomic, strong) CBCentralManager *cbManager;
@property (nonatomic, strong) NSMutableArray *discoveredDevices;

// Controls
@property (nonatomic, strong) UIButton *mainActionBtn;
@property (nonatomic, strong) UISwitch *jitterSwitch;
@property (nonatomic, strong) UISlider *jitterSlider;
@property (nonatomic, strong) UILabel *jitterLabel;

// Route Simulation UI
@property (nonatomic, assign) BOOL isRouteModeEnabled;
@property (nonatomic, strong) MKPointAnnotation *startPin;
@property (nonatomic, strong) MKPointAnnotation *endPin;
@property (nonatomic, strong) MKPolyline *routeLine;
@property (nonatomic, strong) UILabel *speedLabel;
@property (nonatomic, strong) NSTimer *routeTimer;

// Restart Modal
@property (nonatomic, strong) UIVisualEffectView *confirmDialogBackdrop;
@property (nonatomic, strong) UIView *confirmDialogView;
@property (nonatomic, strong) UILabel *timerLabel;
@property (nonatomic, assign) NSInteger countdownTimer;
@property (nonatomic, strong) NSTimer *restartTimer;
@property (nonatomic, assign) BOOL isPendingRestart;
@property (nonatomic, assign) BOOL isMapExpanded;

@property (nonatomic, strong) NSTimer *jitterTimer;
@property (nonatomic, assign) BOOL toolHidden;

+ (instancetype)shared;
- (void)hideToolCompletely;
- (void)showToolGesture;
@end

@implementation WolfoxSpoofOverlay

+ (instancetype)shared {
    static WolfoxSpoofOverlay *instance = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        instance = [[WolfoxSpoofOverlay alloc] initWithFrame:[UIScreen mainScreen].bounds];
    });
    return instance;
}

- (instancetype)initWithFrame:(CGRect)frame {
    if (self = [super initWithFrame:frame]) {
        self.backgroundColor = [UIColor clearColor];
        self.userInteractionEnabled = YES;
        _toolHidden = NO;
        _isMapExpanded = NO;
        _isRouteModeEnabled = NO;
        _discoveredDevices = [NSMutableArray new];
        [self buildUI];
        _jitterTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(tickJitter) userInfo:nil repeats:YES];
    }
    return self;
}

- (void)buildUI {
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;
    CGFloat pW = 340;
    CGFloat pH = 620;
    
    UIBlurEffect *blurEffect = [UIBlurEffect effectWithStyle:UIBlurEffectStyleDark];
    _panel = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    _panel.frame = CGRectMake((sw-pW)/2, (sh-pH)/2, pW, pH);
    _panel.layer.cornerRadius = 24;
    _panel.clipsToBounds = YES;
    _panel.layer.borderWidth = 1.0;
    _panel.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.1].CGColor;
    [self addSubview:_panel];
    
    // Header
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, pW, 100)];
    [_panel.contentView addSubview:header];
    
    UIImageView *logo = [[UIImageView alloc] initWithFrame:CGRectMake(pW-75, 15, 60, 60)];
    logo.image = [UIImage systemImageNamed:@"location.north.circle.fill"];
    logo.tintColor = [UIColor systemGreenColor];
    [header addSubview:logo];
    
    UILabel *titleLbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 25, pW-100, 30)];
    titleLbl.text = WOLFOX_TOOL_NAME;
    titleLbl.textColor = [UIColor whiteColor];
    titleLbl.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    titleLbl.textAlignment = NSTextAlignmentRight;
    [header addSubview:titleLbl];
    
    UILabel *subLbl = [[UILabel alloc] initWithFrame:CGRectMake(20, 50, pW-100, 20)];
    subLbl.text = @"النسخة المطورة - Ultimate Edition";
    subLbl.textColor = [UIColor systemGreenColor];
    subLbl.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    subLbl.textAlignment = NSTextAlignmentRight;
    [header addSubview:subLbl];
    
    _scrollView = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 0, pW, pH)];
    _scrollView.showsVerticalScrollIndicator = NO;
    [_panel.contentView addSubview:_scrollView];
    
    _controlsContainer = [[UIView alloc] initWithFrame:CGRectMake(0, 100, pW, 1000)];
    [_scrollView addSubview:_controlsContainer];
    
    CGFloat cy = 0;
    
    // Map View
    _map = [[MKMapView alloc] initWithFrame:CGRectMake(15, cy, pW-30, 250)];
    _map.layer.cornerRadius = 18;
    _map.delegate = self;
    [_controlsContainer addSubview:_map];
    
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLP:)];
    [_map addGestureRecognizer:lp];
    
    _expandMapBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    _expandMapBtn.frame = CGRectMake(pW-55, cy+10, 35, 35);
    _expandMapBtn.backgroundColor = [UIColor colorWithWhite:0.2 alpha:0.8];
    _expandMapBtn.tintColor = [UIColor whiteColor];
    _expandMapBtn.layer.cornerRadius = 10;
    [_expandMapBtn setImage:[UIImage systemImageNamed:@"arrow.up.left.and.arrow.down.right"] forState:UIControlStateNormal];
    [_expandMapBtn addTarget:self action:@selector(toggleMapSize) forControlEvents:UIControlEventTouchUpInside];
    [_controlsContainer addSubview:_expandMapBtn];
    
    cy += 260;
    
    _mapTypeControl = [[UISegmentedControl alloc] initWithItems:@[@"عادي", @"قمر صناعي", @"هجين"]];
    _mapTypeControl.frame = CGRectMake(15, cy, pW-30, 32);
    _mapTypeControl.selectedSegmentIndex = 0;
    [_mapTypeControl addTarget:self action:@selector(mapTypeChanged:) forControlEvents:UIControlEventValueChanged];
    [_controlsContainer addSubview:_mapTypeControl];
    cy += 45;
    
    _searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(10, cy, pW-20, 50)];
    _searchBar.delegate = self;
    _searchBar.placeholder = @"بحث عن موقع";
    _searchBar.backgroundImage = [UIImage new];
    if (@available(iOS 13.0, *)) {
        _searchBar.searchTextField.backgroundColor = [UIColor colorWithWhite:0.2 alpha:0.6];
        _searchBar.searchTextField.textColor = [UIColor whiteColor];
        _searchBar.searchTextField.textAlignment = NSTextAlignmentRight;
        _searchBar.searchTextField.layer.cornerRadius = 10;
        _searchBar.searchTextField.clipsToBounds = YES;
    }
    [_controlsContainer addSubview:_searchBar];
    cy += 55;

    // Favorites & Save Row
    CGFloat btnW2 = (pW - 40) / 2;
    UIButton *saveBtn = [self modernButtonWithTitle:@"حفظ الموقع" icon:@"square.and.arrow.down.fill" color:[UIColor colorWithRed:0.2 green:0.2 blue:0.25 alpha:0.8] frame:CGRectMake(15, cy, btnW2, 40)];
    [saveBtn addTarget:self action:@selector(addFav) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *favBtn = [self modernButtonWithTitle:@"المفضلة" icon:@"star.fill" color:[UIColor colorWithRed:0.2 green:0.2 blue:0.25 alpha:0.8] frame:CGRectMake(15 + btnW2 + 10, cy, btnW2, 40)];
    [favBtn addTarget:self action:@selector(showFav) forControlEvents:UIControlEventTouchUpInside];
    
    [_controlsContainer addSubview:saveBtn];
    [_controlsContainer addSubview:favBtn];
    cy += 55;

    // Route Simulation Row
    UIButton *routeModeBtn = [self modernButtonWithTitle:@"وضع المسار" icon:@"figure.walk" color:[UIColor systemOrangeColor] frame:CGRectMake(15, cy, btnW2, 40)];
    [routeModeBtn addTarget:self action:@selector(toggleRouteMode) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *startRouteBtn = [self modernButtonWithTitle:@"بدء الرحلة" icon:@"play.fill" color:[UIColor systemGreenColor] frame:CGRectMake(15 + btnW2 + 10, cy, btnW2, 40)];
    [startRouteBtn addTarget:self action:@selector(startSimulation) forControlEvents:UIControlEventTouchUpInside];
    
    [_controlsContainer addSubview:routeModeBtn];
    [_controlsContainer addSubview:startRouteBtn];
    cy += 55;
    
    _speedLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, cy, pW - 30, 20)];
    _speedLabel.text = [NSString stringWithFormat:@"سرعة المحاكاة: %.0f كم/س", [WolfoxSpoofStore shared].travelSpeed];
    _speedLabel.textColor = [UIColor whiteColor];
    _speedLabel.textAlignment = NSTextAlignmentRight;
    _speedLabel.font = [UIFont systemFontOfSize:14];
    [_controlsContainer addSubview:_speedLabel];
    cy += 25;

    UISlider *speedSlider = [[UISlider alloc] initWithFrame:CGRectMake(15, cy, pW - 30, 30)];
    speedSlider.minimumValue = 1.0;
    speedSlider.maximumValue = 120.0;
    speedSlider.value = [WolfoxSpoofStore shared].travelSpeed;
    [speedSlider addTarget:self action:@selector(speedChanged:) forControlEvents:UIControlEventValueChanged];
    [_controlsContainer addSubview:speedSlider];
    cy += 45;
    
    // Grid 3 Row (Hide, Mosques, Bluetooth)
    CGFloat btnW3 = (pW - 50) / 3;
    UIButton *hideBtn = [self modernButtonWithTitle:@"إخفاء" icon:@"eye.slash.fill" color:[UIColor colorWithRed:0.2 green:0.2 blue:0.25 alpha:0.8] frame:CGRectMake(15, cy, btnW3, 40)];
    [hideBtn addTarget:self action:@selector(hideToolCompletely) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *mosqueBtn = [self modernButtonWithTitle:@"مساجد" icon:@"building.columns.fill" color:[UIColor colorWithRed:0.2 green:0.2 blue:0.25 alpha:0.8] frame:CGRectMake(15 + btnW3 + 10, cy, btnW3, 40)];
    [mosqueBtn addTarget:self action:@selector(findAllMosques) forControlEvents:UIControlEventTouchUpInside];
    
    UIButton *btBtn = [self modernButtonWithTitle:@"بلوتوث" icon:@"antenna.radiowaves.left.and.right" color:[UIColor colorWithRed:0.1 green:0.3 blue:0.6 alpha:0.8] frame:CGRectMake(15 + (btnW3 * 2) + 20, cy, btnW3, 40)];
    [btBtn addTarget:self action:@selector(openBluetoothScanner) forControlEvents:UIControlEventTouchUpInside];
    
    [_controlsContainer addSubview:hideBtn];
    [_controlsContainer addSubview:mosqueBtn];
    [_controlsContainer addSubview:btBtn];
    cy += 55;
    
    // Jitter
    _jitterLabel = [[UILabel alloc] initWithFrame:CGRectMake(80, cy, pW - 95, 30)];
    _jitterLabel.text = [NSString stringWithFormat:@"تفعيل الحركة (%.1f أمتار)", [WolfoxSpoofStore shared].jitterDistance];
    _jitterLabel.textColor = [UIColor whiteColor];
    _jitterLabel.textAlignment = NSTextAlignmentRight;
    _jitterLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    [_controlsContainer addSubview:_jitterLabel];
    
    _jitterSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(15, cy, 50, 30)];
    _jitterSwitch.on = [WolfoxSpoofStore shared].isJitterActive;
    [_jitterSwitch addTarget:self action:@selector(toggleJitter:) forControlEvents:UIControlEventValueChanged];
    [_controlsContainer addSubview:_jitterSwitch];
    cy += 35;
    
    _jitterSlider = [[UISlider alloc] initWithFrame:CGRectMake(15, cy, pW - 30, 30)];
    _jitterSlider.minimumValue = 0.1;
    _jitterSlider.maximumValue = 10.0;
    _jitterSlider.value = [WolfoxSpoofStore shared].jitterDistance;
    [_jitterSlider addTarget:self action:@selector(jitterSliderChanged:) forControlEvents:UIControlEventValueChanged];
    [_controlsContainer addSubview:_jitterSlider];
    cy += 45;

    // Main Action Button
    _mainActionBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    _mainActionBtn.frame = CGRectMake(15, cy, pW - 30, 50);
    _mainActionBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.4 blue:1.0 alpha:1.0];
    _mainActionBtn.layer.cornerRadius = 14;
    _mainActionBtn.titleLabel.font = [UIFont systemFontOfSize:18 weight:UIFontWeightBold];
    [_mainActionBtn setTitle:@"تثبيت الموقع المختار" forState:UIControlStateNormal];
    [_mainActionBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [_mainActionBtn addTarget:self action:@selector(applyLocationWithRestart) forControlEvents:UIControlEventTouchUpInside];
    [_controlsContainer addSubview:_mainActionBtn];

    cy += 70;
    _controlsContainer.frame = CGRectMake(0, 0, pW, cy);
    _scrollView.contentSize = CGSizeMake(pW, cy + 100);

    // -------------- Favorites View --------------
    _favView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    _favView.frame = _panel.frame;
    _favView.layer.cornerRadius = 24;
    _favView.clipsToBounds = YES;
    _favView.hidden = YES;
    [self addSubview:_favView];
    
    UIButton *bk = [UIButton buttonWithType:UIButtonTypeSystem];
    bk.frame = CGRectMake(15, 20, 80, 35);
    bk.backgroundColor = [UIColor colorWithWhite:0.3 alpha:0.6];
    [bk setTitle:@"رجوع" forState:UIControlStateNormal];
    [bk setImage:[UIImage systemImageNamed:@"chevron.right"] forState:UIControlStateNormal];
    bk.tintColor = [UIColor whiteColor];
    bk.layer.cornerRadius = 10;
    [bk addTarget:self action:@selector(hideFav) forControlEvents:UIControlEventTouchUpInside];
    [_favView.contentView addSubview:bk];
    
    _table = [[UITableView alloc] initWithFrame:CGRectMake(10, 70, pW - 20, pH - 80) style:UITableViewStylePlain];
    _table.delegate = self;
    _table.dataSource = self;
    _table.backgroundColor = [UIColor clearColor];
    [_favView.contentView addSubview:_table];
    
    // -------------- Bluetooth Scanner View --------------
    _btView = [[UIVisualEffectView alloc] initWithEffect:blurEffect];
    _btView.frame = _panel.frame;
    _btView.layer.cornerRadius = 24;
    _btView.clipsToBounds = YES;
    _btView.hidden = YES;
    [self addSubview:_btView];
    
    UIButton *bkBT = [UIButton buttonWithType:UIButtonTypeSystem];
    bkBT.frame = CGRectMake(15, 20, 80, 35);
    bkBT.backgroundColor = [UIColor colorWithWhite:0.3 alpha:0.6];
    [bkBT setTitle:@"رجوع" forState:UIControlStateNormal];
    [bkBT addTarget:self action:@selector(closeBluetoothScanner) forControlEvents:UIControlEventTouchUpInside];
    [_btView.contentView addSubview:bkBT];
    
    _btTable = [[UITableView alloc] initWithFrame:CGRectMake(10, 100, pW - 20, pH - 110) style:UITableViewStylePlain];
    _btTable.delegate = self;
    _btTable.dataSource = self;
    _btTable.backgroundColor = [UIColor clearColor];
    [_btView.contentView addSubview:_btTable];

    // -------------- Safe Restart Dialog --------------
    _confirmDialogBackdrop = [[UIVisualEffectView alloc] initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleDark]];
    _confirmDialogBackdrop.frame = self.bounds;
    _confirmDialogBackdrop.hidden = YES;
    [self addSubview:_confirmDialogBackdrop];

    _confirmDialogView = [[UIView alloc] initWithFrame:CGRectMake((sw-320)/2, (sh-240)/2, 320, 220)];
    _confirmDialogView.backgroundColor = [UIColor colorWithRed:0.15 green:0.15 blue:0.18 alpha:0.9];
    _confirmDialogView.layer.cornerRadius = 24;
    [_confirmDialogBackdrop.contentView addSubview:_confirmDialogView];

    _timerLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 140, 300, 60)];
    _timerLabel.textAlignment = NSTextAlignmentCenter;
    _timerLabel.textColor = [UIColor whiteColor];
    _timerLabel.font = [UIFont systemFontOfSize:50 weight:UIFontWeightHeavy];
    [_confirmDialogView addSubview:_timerLabel];
}

- (UIButton *)modernButtonWithTitle:(NSString *)title icon:(NSString *)iconName color:(UIColor *)color frame:(CGRect)frame {
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = frame;
    btn.backgroundColor = color;
    btn.layer.cornerRadius = 10;
    btn.tintColor = [UIColor whiteColor];
    if (iconName) [btn setImage:[UIImage systemImageNamed:iconName] forState:UIControlStateNormal];
    [btn setTitle:[NSString stringWithFormat:@" %@", title] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    return btn;
}

// -------------- Route Simulation Logic --------------
- (void)toggleRouteMode {
    self.isRouteModeEnabled = !self.isRouteModeEnabled;
    if (self.isRouteModeEnabled) {
        if (self.startPin) [self.map removeAnnotation:self.startPin];
        if (self.endPin) [self.map removeAnnotation:self.endPin];
        if (self.routeLine) [self.map removeOverlay:self.routeLine];
        self.startPin = nil; self.endPin = nil; self.routeLine = nil;
        [self showToast:@"وضع المسار: اضغط مطولاً لتحديد البداية ثم النهاية"];
    } else {
        [self showToast:@"تم العودة لوضع الموقع الثابت"];
    }
}

- (void)speedChanged:(UISlider *)sender {
    [WolfoxSpoofStore shared].travelSpeed = sender.value;
    _speedLabel.text = [NSString stringWithFormat:@"سرعة المحاكاة: %.0f كم/س", sender.value];
}

- (void)startSimulation {
    if (!self.startPin || !self.endPin) {
        [self showToast:@"يرجى تحديد نقطة البداية والنهاية أولاً"];
        return;
    }
    [WolfoxSpoofStore shared].isRouteActive = YES;
    [WolfoxSpoofStore shared].startCoords = self.startPin.coordinate;
    [WolfoxSpoofStore shared].endCoords = self.endPin.coordinate;
    [WolfoxSpoofStore shared].currentMovingCoords = self.startPin.coordinate;
    
    if (self.routeTimer) [self.routeTimer invalidate];
    self.routeTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(tickSimulation) userInfo:nil repeats:YES];
    [self showToast:@"بدأت المحاكاة بنجاح 🚀"];
}

- (void)tickSimulation {
    WolfoxSpoofStore *store = [WolfoxSpoofStore shared];
    CLLocationCoordinate2D current = store.currentMovingCoords;
    CLLocationCoordinate2D target = store.endCoords;
    
    double step = (store.travelSpeed / 3600.0) * 0.00001; 
    
    double dLat = target.latitude - current.latitude;
    double dLon = target.longitude - current.longitude;
    double dist = sqrt(dLat*dLat + dLon*dLon);
    
    if (dist < step) {
        store.currentMovingCoords = target;
        [self.routeTimer invalidate];
        self.routeTimer = nil;
        [self showToast:@"وصلت للوجهة النهائية 🏁"];
    } else {
        double ratio = step / dist;
        store.currentMovingCoords = CLLocationCoordinate2DMake(current.latitude + dLat*ratio, current.longitude + dLon*ratio);
    }
    
    // Update map pin
    if (self.pin) self.pin.coordinate = store.currentMovingCoords;
}

- (void)showToast:(NSString *)msg {
    UILabel *toast = [[UILabel alloc] initWithFrame:CGRectMake(20, self.bounds.size.height - 100, self.bounds.size.width - 40, 40)];
    toast.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.7];
    toast.textColor = [UIColor whiteColor];
    toast.textAlignment = NSTextAlignmentCenter;
    toast.text = msg;
    toast.layer.cornerRadius = 20;
    toast.clipsToBounds = YES;
    [self addSubview:toast];
    [UIView animateWithDuration:2.0 delay:1.0 options:UIViewAnimationOptionCurveEaseOut animations:^{ toast.alpha = 0.0; } completion:^(BOOL f){ [toast removeFromSuperview]; }];
}

// -------------- Original Logic Hooks --------------
- (void)mapTypeChanged:(UISegmentedControl *)sender {
    switch (sender.selectedSegmentIndex) {
        case 0: self.map.mapType = MKMapTypeStandard; break;
        case 1: self.map.mapType = MKMapTypeSatellite; break;
        case 2: self.map.mapType = MKMapTypeHybrid; break;
    }
}

- (void)toggleMapSize {
    self.isMapExpanded = !self.isMapExpanded;
    [UIView animateWithDuration:0.3 animations:^{
        if (self.isMapExpanded) {
            self.map.frame = CGRectMake(15, 0, self.panel.bounds.size.width - 30, self.panel.bounds.size.height - 50);
            self.controlsContainer.alpha = 0.0;
        } else {
            self.map.frame = CGRectMake(15, 0, self.panel.bounds.size.width - 30, 250);
            self.controlsContainer.alpha = 1.0;
        }
    }];
}

- (void)handleLP:(UILongPressGestureRecognizer *)s {
    if (s.state == UIGestureRecognizerStateBegan) {
        CLLocationCoordinate2D c = [_map convertPoint:[s locationInView:_map] toCoordinateFromView:_map];
        if (self.isRouteModeEnabled) {
            if (!self.startPin) {
                self.startPin = [[MKPointAnnotation alloc] init];
                self.startPin.coordinate = c;
                self.startPin.title = @"بداية المسار";
                [self.map addAnnotation:self.startPin];
            } else if (!self.endPin) {
                self.endPin = [[MKPointAnnotation alloc] init];
                self.endPin.coordinate = c;
                self.endPin.title = @"نهاية المسار";
                [self.map addAnnotation:self.endPin];
                CLLocationCoordinate2D coords[2] = {self.startPin.coordinate, self.endPin.coordinate};
                self.routeLine = [MKPolyline polylineWithCoordinates:coords count:2];
                [self.map addOverlay:self.routeLine];
            }
        } else {
            [self moveMapToCoordinate:c];
        }
    }
}

- (void)moveMapToCoordinate:(CLLocationCoordinate2D)coord {
    if (_pin) [_map removeAnnotation:_pin];
    _pin = [[MKPointAnnotation alloc] init];
    _pin.coordinate = coord;
    _pin.title = @"الموقع المحدد";
    [_map addAnnotation:_pin];
    [_map setRegion:MKCoordinateRegionMakeWithDistance(coord, 3000, 3000) animated:YES];
}

- (MKOverlayRenderer *)mapView:(MKMapView *)mapView rendererForOverlay:(id<MKOverlay>)overlay {
    if ([overlay isKindOfClass:[MKPolyline class]]) {
        MKPolylineRenderer *r = [[MKPolylineRenderer alloc] initWithPolyline:overlay];
        r.strokeColor = [UIColor systemBlueColor];
        r.lineWidth = 5.0;
        return r;
    }
    return nil;
}

- (void)toggleJitter:(UISwitch *)sender { [WolfoxSpoofStore shared].isJitterActive = sender.isOn; [[WolfoxSpoofStore shared] save]; }
- (void)jitterSliderChanged:(UISlider *)sender { [WolfoxSpoofStore shared].jitterDistance = sender.value; _jitterLabel.text = [NSString stringWithFormat:@"تفعيل الحركة (%.1f أمتار)", sender.value]; [[WolfoxSpoofStore shared] save]; }
- (void)tickJitter {
    if ([WolfoxSpoofStore shared].isActive && [WolfoxSpoofStore shared].isJitterActive) {
        double dist = [WolfoxSpoofStore shared].jitterDistance / 111111.0;
        [WolfoxSpoofStore shared].driftLatitude = ((double)arc4random() / 0xFFFFFFFF) * dist - (dist/2);
        [WolfoxSpoofStore shared].driftLongitude = ((double)arc4random() / 0xFFFFFFFF) * dist - (dist/2);
    }
}

- (void)applyLocationWithRestart {
    if (!_pin) return;
    [WolfoxSpoofStore shared].isActive = YES;
    [WolfoxSpoofStore shared].hasStoredLocation = YES;
    [WolfoxSpoofStore shared].fakeCoords = _pin.coordinate;
    [[WolfoxSpoofStore shared] save];
    _isPendingRestart = YES; _panel.hidden = YES; _confirmDialogBackdrop.hidden = NO;
    self.countdownTimer = 5; _timerLabel.text = @"5";
    self.restartTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(tickRestartTimer) userInfo:nil repeats:YES];
}

- (void)tickRestartTimer {
    self.countdownTimer--; _timerLabel.text = [NSString stringWithFormat:@"%ld", (long)self.countdownTimer];
    if (self.countdownTimer <= 0) { [self.restartTimer invalidate]; wolfox_safe_exit(0); }
}

- (void)hideToolCompletely { _panel.hidden = YES; _toolHidden = YES; [self showToast:@"تم إخفاء الأداة. انقر ثلاث مرات بإصبعين للإظهار."]; }
- (void)showToolGesture { _panel.hidden = NO; _toolHidden = NO; [self bringSubviewToFront:_panel]; }

// TableView & Bluetooth
- (NSInteger)tableView:(UITableView *)t numberOfRowsInSection:(NSInteger)s { return t == _btTable ? self.discoveredDevices.count : [WolfoxSpoofStore shared].favorites.count; }
- (UITableViewCell *)tableView:(UITableView *)t cellForRowAtIndexPath:(NSIndexPath *)i { 
    UITableViewCell *c = [t dequeueReusableCellWithIdentifier:@"c"]; if(!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"c"];
    c.backgroundColor = [UIColor clearColor]; c.textLabel.textColor = [UIColor whiteColor]; c.detailTextLabel.textColor = [UIColor lightGrayColor];
    if (t == _btTable) {
        NSDictionary *d = self.discoveredDevices[i.row];
        NSString *name = d[@"name"] ?: d[@"identifier"] ?: @"Bluetooth Device";
        c.textLabel.text = name;
        if (d[@"rssi"]) c.detailTextLabel.text = [NSString stringWithFormat:@"RSSI: %@", d[@"rssi"]];
    } else {
        NSDictionary *fav = [WolfoxSpoofStore shared].favorites[i.row];
        NSString *fname = fav[@"name"] ?: [NSString stringWithFormat:@"%.6f, %.6f", [fav[@"lat"] doubleValue], [fav[@"lon"] doubleValue]];
        c.textLabel.text = fname;
        c.detailTextLabel.text = [NSString stringWithFormat:@"Lat: %@ Lon: %@", fav[@"lat"], fav[@"lon"]];
    }
    return c;
}
- (void)addFav { if(!_pin) return; [[WolfoxSpoofStore shared].favorites addObject:@{@"name":@"Saved", @"lat":@(_pin.coordinate.latitude), @"lon":@(_pin.coordinate.longitude)}]; [[WolfoxSpoofStore shared] save]; [self showToast:@"تم حفظ الموقع إلى المفضلة"]; }
- (void)showFav { _panel.hidden = YES; _favView.hidden = NO; [_table reloadData]; }
- (void)hideFav { _favView.hidden = YES; _panel.hidden = NO; }
- (void)findAllMosques { [self showToast:@"جاري البحث عن المساجد القريبة..."]; }
- (void)openBluetoothScanner { _panel.hidden = YES; _btView.hidden = NO; }
- (void)closeBluetoothScanner { _btView.hidden = YES; _panel.hidden = NO; }
- (void)centralManagerDidUpdateState:(CBCentralManager *)c {}
@end

// -------------- Location Spoofing Logic --------------
CLLocationCoordinate2D my_coordinate(CLLocation *self, SEL _cmd) {
    WolfoxSpoofStore *store = [WolfoxSpoofStore shared];
    if (store.isActive) {
        CLLocationCoordinate2D base = store.isRouteActive ? store.currentMovingCoords : store.fakeCoords;
        return CLLocationCoordinate2DMake(base.latitude + store.driftLatitude, base.longitude + store.driftLongitude);
    }
    Method m = class_getInstanceMethod([CLLocation class], @selector(coordinate));
    CLLocationCoordinate2D (*orig)(id, SEL) = (CLLocationCoordinate2D (*)(id, SEL))method_getImplementation(m);
    return orig(self, _cmd);
}

// Startup
__attribute__((constructor)) static void init_tool() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [WolfoxSpoofStore shared];
        // Hooks for Location & System (Simplified for this version)
        Class cls = [CLLocation class];
        Method m = class_getInstanceMethod(cls, @selector(coordinate));
        method_setImplementation(m, (IMP)my_coordinate);
        
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIWindow *win = [UIApplication sharedApplication].keyWindow;
            [win addSubview:[WolfoxSpoofOverlay shared]];
        });
    });
}
