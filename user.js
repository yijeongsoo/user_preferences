/*
Mozilla User Preferences

pref.js is the actual preference settings that will be delivered into Firefox / Thunderbird.
user.js allows you to override that setting and set preferences in pref.js.
This means that user.js will write things in pref.js and will be saved.
If you wish to keep original settings, please have a separate copy of pref.js so that the browser does not run into malfunction.

*/


// Privacy Settings referenced from:
// https://www.ghacks.net/overview-firefox-aboutconfig-security-privacy-preferences/
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections
//

//---------------------------------------------------------------------------------------------------------------

/*
	Trusted Reursive Resolver(TRR Settings)
*/

// If you wish to know about TRR, please refer to the Related Link: 
// https://urldefense.proofpoint.com/v2/url?u=https-3A__wiki.mozilla.org_Trusted-5FRecursive-5FResolver-23network.trr.mode&d=DwICaQ&c=slrrB7dE8n7gBJbeO0g-IQ&r=cgjzrGmZ4b3J45_kXVG17A&m=iv63y-rj5n_Z6KLgy0EMIhAYZ67cPJTdj14g1Xmw2Mo&s=SBJqyWt2YlALYET226nl6wo7IvZow7l_ZwEC74TV1iY&e=
user_pref("network.trr.mode", 5);
/*
Settings:

0 - Off (default). use standard native resolving only (don't use TRR at all)
1 - Reserved (used to be Race mode)
2 - First. Use TRR first, and only if the name resolve fails use the native resolver as a fallback.
3 - Only. Only use TRR. Never use the native (This mode also requires the bootstrapAddress pref to be set)
4 - Reserved (used to be Shadow mode)
5 - Off by choice. This is the same as 0 but marks it as done by choice and not done by default.
*/

//---------------------------------------------------------------------------------------------------------------

/*
	Network Settings
*/

// Disable IPv6 Settings.
user_pref("network.dns.disableIPv6", true);
// If your OS or ISP does not support IPv6, 
// there is no reason to have this preference set to false.

// Enable punycode displaying to prevent spoofing
user_pref("network.IDN_show_punycode", true);
// punycode display to prevent from spoofing(This is something frequently happening recently) 
// [IDN homograph attacks](https://www.xudongz.com/blog/2017/idn-phishing/);

user_pref("network.http.sendRefererHeader", 0);
/*
Tells website where you came from. Disabling may break some sites.
0 = Disable referrer headers. 
1 = Send only on clicked links.
2 = (default) Send for links and image.
*/

//Disable referrer headers between https websites.      
user_pref("network.http.sendSecureXSiteReferrer", false);
      
//Send fake referrer (if choose to send referrers);.  
user_pref("network.http.referer.spoofSource", true);

user_pref("network.http.use-cache", false);

//Mozilla’s built in tracking protection.  
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.resistFingerprinting", true);


//Disable network predictor
user_pref("network.predictor.enabled", false);
//By changing this value to true, you allow the browser to predict which pages you might visit at some point, and store them in cache.


user_pref("network.dns.disablePrefetch", true);
/*
DNS prefetching was implemented in Firefox 3.5 to improve page load time. 
This feature allows Firefox to perform domain name resolution proactively and in parallel for hyperlinks, images, CSS, JavaScript, and other webpage content.
Note: To disable DNS prefetching using about:config,
you will need to add network.dns.disablePrefetch as a new boolean preference and set the value to true.
*/

user_pref("network.prefetch-next", false);
/*
Link prefetching is when a webpage hints to the browser that certain pages are likely to be visited, 
so the browser downloads them immediately so they can be displayed immediately when the user requests it. 
*/

// Disable prefetch link on hover. 
user_pref("network.http.speculative-parallel-limit", 0);
/*
Firefox by default pre-loads the website if you hover your mouse over the link.
values from 6 to 0 - 6 is activating the system - 0 is disactivating the prefetch
*/

user_pref("browser.send_pings", false);
user_pref("browser.send_pings.require_same_host", true);
//Only send pings if send and receiving host match (same website);.

// George - Oct. 29th - "detectportal disabling"
user_pref("captivedetect.canonicalURL", "");
user_pref("network.connectivity-service.IPv4.url", "");
user_pref("network.connectivity-service.IPv6.url", "");

user_pref("network.captive-portal-service.enabled", false);

//---------------------------------------------------------------------------------------------------------------

/*
	Disable Google Safe Browsing and malware and phishing protection.
*/

/*
The following lines stop sending links and downloading lists from google. 
This imposes a security risk, but privacy improvement.
Note: this list may be incomplete as firefox updates, be sure to search for browser.safebrowsing.provider.google*
Also simply setting safebrowsing.*.enabled to false should make setting the URL's to blank redundant, but better to be safe.
If you see anything pointing google, probably best to nuke it.
*/
        
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);  
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.provider.google4.dataSharing.enabled", ");");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.reportURL", "");
user_pref("browser.safebrowsing.provider.google4.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google4.lists", "");
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharingURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharing.enabled", false);
user_pref("browser.safebrowsing.provider.google4.advisoryURL", "");
user_pref("browser.safebrowsing.provider.google4.advisoryName", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google.reportURL", "");
user_pref("browser.safebrowsing.provider.google.reportPhishMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.reportMalwareMistakeURL", "");
user_pref("browser.safebrowsing.provider.google.pver", "");
user_pref("browser.safebrowsing.provider.google.lists", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.advisoryURL", "");
user_pref("browser.safebrowsing.downloads.remote.url", "");

// Disable search suggestions.
user_pref("browser.search.suggest.enabled", false);

user_pref("browser.search.update", false);

// 
user_pref("privacy.history.custom", true);

//---------------------------------------------------------------------------------------------------------------

/*
	DOM(Document Object Model) storage (Or Web storage) 
	(Also known as Client-side session and Persistent storage)
*/

//Disable web storage services
user_pref("dom.storage.enabled", false);

//Disable anyone from knowing your current battery information
user_pref("dom.battery.enabled", false);
/*
BatteryManager can give information about the current battery status. 
The problem with others accessing this data is that certain plug-ins and add-ons will be disactivated when battery goes low.
Potential vulnerability exists with others knowing when this happens.

By the way, Same applies to your smartphone as well.
*/

user_pref("dom.enable_performance", false);
//Gamepad connections can be 
user_pref("dom.gamepad.enabled", false);

user_pref("dom.indexedDB.enabled", false);
user_pref("dom.enable_resource_timing", false);
user_pref("dom.enable_user_timing", false); //?
user_pref("dom.event.highrestimestamp.enabled", true);

// Disable ServiceWorkers by default
user_pref("dom.serviceWorkers.enabled", false);


//---------------------------------------------------------------------------------------------------------------

/*
    Cache Settings
*/

// Disable caching.
user_pref("browser.cache.disk.enable", false);
// Disabling access to memory through cache.
user_pref("browser.cache.memory.enable", false);
// Disable offline caching (saving of form data)
user_pref("browser.cache.offline.enable", false);
//Disables caching for ssl connections.
user_pref("browser.cache.disk_cache_ssl", false);

/*
DNS (Domain Name System) allows an application to translate domain names into IP addresses. 
To reduce load on DNS servers and to speed up response time, Mozilla caches DNS results. 
This preference controls the maximum number of results to cache.
*/
user_pref("network.dnsCacheEntries", 100);
// Number of cached DNS entries. Lower number = More requests but less data stored.
// Default: 20
user_pref("network.dnsCacheExpiration", 60);
// Time DNS entries are cached in seconds.
// Default: 60

// Block websites from reading or modifying Clipboard contents in Firefox
user_pref("dom.event.clipboardevents.enabled", false);

user_pref("extensions.getAddons.cache.enabled", false);
//---------------------------------------------------------------------------------------------------------------

/*
    Disk Settings
*/

// Disk activity: Disable Browsing History Storage
user_pref("permissions.memory_only", true);
user_pref("browser.download.manager.retention", 1);
user_pref("security.nocertdb", true);

// Disk activity: TBB Directory Isolation
user_pref("browser.download.useDownloadDir", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.download.manager.addToRecentDocs", false);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: I/O permissions
*/

user_pref("device.sensors.enabled", false); .
user_pref("permissions.default.camera", 0);
user_pref("permissions.default.desktop-notification", 0);
user_pref("permissions.default.geo", 0);
user_pref("permissions.default.microphone", 0);
// Disable Geolocation.
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");

user_pref("browser.search.countryCode", "US")
user_pref("browser.search.region", "US");
// Disables the geographic tracking of the user's IP
user_pref("browser.search.geoip.url", "");

// Prevent website tracking clicks.
user_pref("toolkit.telemetry.cachedClientID", "");

// Following are various web I/O enable/disable prompts
// Suppress ALT and SHIFT events"
user_pref("privacy.suppressModifierKeyEvents", true); 
// Disable SpeechSynthesis API
user_pref("media.webspeech.synth.enabled", false); 
// Disable Web Audio API
user_pref("dom.webaudio.enabled", false); 
// Spoof single-core cpu
user_pref("dom.maxHardwareConcurrency", 1); 
// Always disable Touch API
user_pref("dom.w3c_touch_events.enabled", 0); 
user_pref("dom.w3c_pointer_events.enabled", false);
// Disable WebVR for now
user_pref("dom.vr.enabled", false); 

//---------------------------------------------------------------------------------------------------------------
/*
	Miscellaneous Privacy: Autocorrect & Autofill
*/

user_pref("browser.formfill.enable", false);
// Do not automatically fill sign-in forms with known usernames and passwords; instead, act as though there are multiple usernames/password pairs remembered for the form (fill password after username has been manually typed);. 
user_pref("signon.autofillForms", false);
user_pref("signon.rememberSignons", false);
user_pref("dom.forms.autocomplete.formautofill", false);
user_pref("browser.urlbar.autoFill", false);
user_pref("extensions.formautofill.available", "detect");

// Block your browser from attaining your credit card information
user_pref("extensions.formautofill.creditCards.available", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

//Block your browser from autofilling addresses
user_pref("extensions.formautofill.addresses.enabled", false);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Plugins
*/

user_pref("plugin.state.flash", 1);
/*
The default state of the Flash plugin.
	0: turns off the Flash plugin in Firefox.
	1: sets the Flash plugin to ask to activate.
	2: enables the Flash plugin.
*/

// If TRUE, scans the Windows Registry key for plugin references. If found, adds them to Firefox.
user_pref("plugin.scan.plid.all", false);

// Disable site reading installed plugins.
user_pref("plugins.enumerable_names", "");

// The default state of the Java plugin.
user_pref("plugin.state.java", 1);
/*
	0: turns off the Java plugin in Firefox.
	1: sets the Java plugin to ask to activate.
	2: enables the Java plugin.
*/

//---------------------------------------------------------------------------------------------------------------

/*
	Cookie Settings
*/

user_pref("network.cookie.alwaysAcceptSessionCookies", false);
//Disables acceptance of session cookies. 
//Prompt for sessions cookies as it would for other cookies. (Default)   

user_pref("network.cookie.cookieBehavior", 1);
/*
Disable cookies.
0 = All cookies are allowed. (Default); 
1 = Only cookies from the originating server are allowed. (block third party cookies);
2 = No cookies are allowed. 
3 = Third-party cookies are allowed only if that site has stored cookies already from a previous visit 
*/

user_pref("network.cookie.lifetimePolicy", 1);
/*
cookies are deleted at the end of the session
0 = The cookie's lifetime is supplied by the server. (Default); 
1 = The user is prompted for the cookie's lifetime. 
2 = The cookie expires at the end of the session (when the browser closes);. 
3 = The cookie lasts for the number of days specified by network.cookie.lifetime.days.   
*/
// If network.cookie.lifetimePolicy = 3, the user will specify the cookie lifetime
// user_pref("network.cookie.lifetime.days", 30)

user_pref("places.history.enabled", false);
//Disables recording of visited websites. 
//If you wish to enable your history page, do not change this value to false

//---------------------------------------------------------------------------------------------------------------

/*
	Third Party Access Permission
*/

//Related to WebRTC(Real-Time Communication) technology
//Supplementary Link: https://thesafety.us/what-is-webrtc
user_pref("media.peerconnection.enabled", false);    
user_pref("network.websocket.enabled", false);
/*WebSockets is a technology that makes it possible to open an interactive communication 
session between the user's browser and a server. (May leak IP when using proxy/VPN);
*/   
user_pref("loop.enabled", false);
/*  Disable 3rd party closed-source Hello integration.
  Note: only affects older versions of firefox as "Hello" has been discontinued as in favor of webrtc: https://support.mozilla.org/en-US/kb/hello-status
 */ 

user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.site", "");
user_pref("extensions.pocket.oAuthConsumerKey", "");
user_pref("extensions.pocket.api", "");
/*
Pocket(Previously "Read It Later") saves sites, videos, articles for the user to view later.
This feature is built into Firefox.

Disable 3rd party closed-source Pocket integration.
Note, this is browser.pocket.enabled for older versions of firefox
*/

// Provides web applications with information about video playback statistics such as the framerate.
user_pref("media.video_stats.enabled", false);


//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Site Icons
*/

user_pref("browser.chrome.site_icons", false); 
/*
The access of site icons(Mini-icons of the current website, i.e. the "G" of Google)
might pose risk of someone else to access my files or input privacy threats to my file.
*/
// This preference set to false will override the effects of browser.chrome.load_toolbar_icons, 
// browser.chrome.favicons, and browser.chrome.image_icons.max_size.

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Homepage settings
*/

user_pref("browser.selfsupport.url", "");
user_pref("browser.aboutHomeSnippets.updateUrL", "");
/*
Can call home to every time firefox is started or home page is visited.
[https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections]
[http://kb.mozillazine.org/Connections_established_on_startup_-_Firefox]
*/

// Set browser's milestone to ignore
user_pref("browser.startup.homepage_override.mstone", "ignore");
/*
The browser’s milestone (e.g., “rv:1.8.1.1”); from the last successful startup of the browser. 
If it differs from the browser’s actual milestone, it is assumed an upgrade has occurred, 
and the user is redirected to the homepage override URL. 
If its value is “ignore”, then the redirect does not occur and the preference is not updated. 
*/

//Make sure that no other entity will overwrite the homepage URL.
user_pref("browser.startup.homepage_override.buildID" : ""
user_pref("startup.homepage_welcome_url" : ""
user_pref("startup.homepage_welcome_url.additional" : ""
user_pref("startup.homepage_override_url" : ""

// Defines if Firefox is started in private browsing mode on start.
user_pref("browser.privatebrowsing.autostart", true);

// If a third party manages to alternate your homepage settings, disabling this will prevent redirecting from homepages
user_pref("browser.newtabpage.enabled", false);
// No preloading the new tab pages
user_pref("browser.newtabpage.preload", false); 
//Make sure new window opening links open new tabs - to prevent fullscreen pop-ups.
user_pref("browser.link.open_newwindow.restriction", 0);


//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Shutdown Privacy Settings
*/

// Whether the browsing history is automatically cleared on shutdown.
user_pref("privacy.sanitize.sanitizeOnShutdown", true);

// The following are clear on shutdown settings.
// Set as TRUE to clear on Shutdown

user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.openWindows", true);
user_pref("privacy.clearOnShutdown.passwords", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.siteSettings", true);

// The following are Clear Browsing Data dialog options
// Defines the items that are selected automatically when you bring up the Clear Browsing Data dialog (using Ctrl-Shift-Del for instance). True means the data set is selected, false it is not.

user_pref("privacy.cpd.cache", true);
user_pref("privacy.cpd.cookies", true);
user_pref("privacy.cpd.downloads", true);
user_pref("privacy.cpd.formdata", true);
user_pref("privacy.cpd.history", true);
user_pref("privacy.cpd.offlineApps", true);
user_pref("privacy.cpd.openWindows", true);
user_pref("privacy.cpd.passwords", true);
user_pref("privacy.cpd.sessions", true);
user_pref("privacy.cpd.siteSettings", true);


//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Toolkit Settings
*/

//Disable Telemetry Settings
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);


//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Data Reporting - Health report
*/

// This section also relates to the disclosure of 
// https://urldefense.proofpoint.com/v2/url?u=https-3A__bugs.torproject.org_10367&d=DwICaQ&c=slrrB7dE8n7gBJbeO0g-IQ&r=cgjzrGmZ4b3J45_kXVG17A&m=iv63y-rj5n_Z6KLgy0EMIhAYZ67cPJTdj14g1Xmw2Mo&s=eyKMexer3Hqqh5Ela4f96d-CKe4_UGxj06ovBARASaE&e=
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.about.reportUrl", "data:text/plain",);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Security Concerns
*/

// The Man In The Middle Attack prevention mechanism
user_pref("security.certerrors.mitm.priming.enabled", false);
user_pref("security.certerrors.mitm.priming.endpoint", "https://mitmdetection.services.mozilla.com/");
user_pref("security.certerrors.mitm.auto_enable_enterprise_roots", true); 

// Disable the "Refresh" prompt that is displayed for stale profiles.
user_pref("browser.disableResetPrompt", true);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: User settings
*/

// Disables the 'know your rights' button from displaying on first run
user_pref("browser.rights.3.shown", true);

user_pref("identity.fxaccounts.enabled", false); // Disable sync by default
// Don't promote sync
user_pref("browser.syncPromoViewsLeftMap", "{\"addons\":0, \"passwords\":0, \"bookmarks\":0}"); 

// Never sync prefs, addons, or tabs with other browsers
user_pref("services.sync.engine.prefs", false); 
user_pref("services.sync.engine.addons", false);
user_pref("services.sync.engine.tabs", false);

//disable Add-ons from using the cache
user_pref("extensions.getAddons.cache.enabled", false);

// No experimental features by Mozilla implemented
user_pref("experiments.enabled", false);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Fingerprint Settings
*/

//Disable device sensors as possible fingerprinting vector 
user_pref("webgl.disable-extensions", true);
user_pref("webgl.disable-fail-if-major-performance-caveat", true);
user_pref("webgl.enable-webgl2", false);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);

//---------------------------------------------------------------------------------------------------------------

/*
	Miscellaneous Privacy: Presentation API
*/

// Disable Presentation API
user_pref("dom.presentation.controller.enabled", false);
user_pref("dom.presentation.enabled", false);
user_pref("dom.presentation.discoverable", false);
user_pref("dom.presentation.discoverable.encrypted", false);
user_pref("dom.presentation.discovery.enabled", false);
user_pref("dom.presentation.receiver.enabled", false);
user_pref("dom.audiochannel.audioCompeting", false);
user_pref("dom.audiochannel.mediaControl", false);

//---------------------------------------------------------------------------------------------------------------


