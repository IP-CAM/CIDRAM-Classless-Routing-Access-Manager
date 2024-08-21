<?php
/**
 * This file is an optional module for CIDRAM.
 * Its purpose is to block bad bots and old browsers.
 *
 * BOBUAM COPYRIGHT 2021 and beyond by David MacMathan (macmathan).
 * @link https://macmathan.info/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 * @link https://cidram.github.io/
 *
 * License: GNU/GPLv2
 * @link https://www.gnu.org/licenses/gpl-2.0.html
 * @see LICENSE.txt
 *
 * Thanks to:
 * - MickeyRouch for some signature ideas once shared on the now defunct
 *   spambotsecurity forum.
 * - JamesC for some clever ideas and code concerning configuration defaults.
 *
 * BOBUAM contains some data from the Wordpress plugin Stop Bad Bots (v3.8) by
 * William "Bill" Minozzi.
 * @link https://www.stopbadbots.com/
 *
 * This file: Bot Or Browser User Agent Module (last modified: 2024.08.18).
 *
 * False positive risk (an approximate, rough estimate only): « [ ]Low [x]Medium [ ]High »
 */

/** Safety. */
if (!isset($this->CIDRAM['ModuleResCache'])) {
    $this->CIDRAM['ModuleResCache'] = [];
}

/** Defining as closure for later recall (no params; no return value). */
$this->CIDRAM['ModuleResCache'][$Module] = function () {
    /** Guard. */
    if (empty($this->BlockInfo['IPAddr'])) {
        return;
    }

    /** Fetch hostname. */
    if (empty($this->CIDRAM['Hostname'])) {
        $this->CIDRAM['Hostname'] = $this->dnsReverse($this->BlockInfo['IPAddr']);
    }

    /** Fetch options. */
    $Options = array_flip(explode("\n", $this->Configuration['bobuam']['options']));

    /** Sanity checks (checking for ambiguous and clearly malformed user agents). */
    if ($this->Configuration['bobuam']['sanity_check'] === 'yes') {
        $Masquerade = [
            $this->L10N->getString('bobuam_masquerade'),
            $this->L10N->getString($this->Configuration['bobuam']['reason_masquerade']) ?: $this->Configuration['bobuam']['reason_masquerade'] ?: $this->L10N->getString('denied')
        ];
        $Ambiguous = [
            $this->L10N->getString('bobuam_ambiguous'),
            $this->L10N->getString($this->Configuration['bobuam']['reason_ambiguous']) ?: $this->Configuration['bobuam']['reason_ambiguous'] ?: $this->L10N->getString('denied')
        ];
        $Malformed = [
            $this->L10N->getString('bobuam_malformed'),
            $this->L10N->getString($this->Configuration['bobuam']['reason_malformed']) ?: $this->Configuration['bobuam']['reason_malformed'] ?: $this->L10N->getString('denied')
        ];
        if ($this->trigger(preg_match('%(?i)(?=.*nutch)(?:google|bing|opera)bot%', $this->BlockInfo['UA']), $Masquerade[0] . ' (NB)', $Masquerade[1])) {
            $this->enactOptions('Masquerade:', $Options);
        }
        if (
            $this->trigger(preg_match('%(?i)(?=.*opera)(?=.*(?:firefox|msie)).*%', $this->BlockInfo['UA']), $Ambiguous[0] . ' (OFM)', $Ambiguous[1]) ||
            $this->trigger(preg_match('%(?i)(?=.*firefox)(?=.*(?:chrom(?:e|ium)|msie)).*%', $this->BlockInfo['UA']), $Ambiguous[0] . ' (FCM)', $Ambiguous[1]) ||
            $this->trigger(preg_match('%(?i:(?=(?:.*)(?:mozilla.*){2,})|(?=.*(?:msie.*){2,})).*%', $this->BlockInfo['UA']), $Ambiguous[0] . ' (MM)', $Ambiguous[1])
        ) {
            $this->enactOptions('Ambiguous:', $Options);
        }
        if (
            $this->trigger(preg_match('%(?i)(?=.*gecko\/\d*)(?=.*rv:([\d\.]*)).*firefox\/(?!\1)%', $this->BlockInfo['UA'], $Ver) && $Ver[1] !== '109.0', $Malformed[0] . ' (FF)', $Malformed[1]) ||
            $this->trigger(preg_match('%(?i)(?!.*gecko\/20100101).*rv:([\d\.]*).*gecko\/(?!\1)%', $this->BlockInfo['UA'], $Ver) && $Ver[1] !== '109.0', $Malformed[0] . ' (MZ)', $Malformed[1]) ||
            $this->trigger(preg_match('%(?:.* Chrome\/(\d*\.)).* Edg\/(?!\1)%', $this->BlockInfo['UA']), $Malformed[0] . ' (EC)', $Malformed[1]) ||
            $this->trigger(preg_match('%(?i)(?!.*safari\/\d{3,5}(?![\w]))(?=safari).*%', $this->BlockInfo['UA']), $Malformed[0] . ' (S)', $Malformed[1]) ||
            $this->trigger(preg_match('%(?i)(?:Microsoft Internet Explorer|ft NT (?:[12789]|[2-9]\d)\.)%', $this->BlockInfo['UA']), $Malformed[0] . ' (MS)', $Malformed[1]) ||
            $this->trigger(preg_match('%^(?=.*Windows NT \d\d\.)(?!.*Kindle\/.*)(?i)(?!.*mobile.*)(?!.*googlebot*)(?!.*android*)(?!.*edge?\/.*).*Version\/.*$%', $this->BlockInfo['UA']), $Malformed[0] . ' (WS)', $Malformed[1])
        ) {
            $this->enactOptions('Malformed:', $Options);
        }
    }

    /** Signatures for recognised malicious and unwanted bots. */
    if ($this->Configuration['bobuam']['block_bots'] === 'yes') {
        $Bot = [
            $this->L10N->getString('bobuam_bot'),
            $this->L10N->getString($this->Configuration['bobuam']['reason_bot']) ?: $this->Configuration['bobuam']['reason_bot'] ?: $this->L10N->getString('denied')
        ];
        if (
            $this->trigger(preg_match('%(?:\+5Bot\/|\; Windows (?:NT|XP|20\d+)\\)|0(?:\.9xpre12|07(?:AC|ac)9|1NET\.COM)|1(?:5miles\.com|92\.comAgent)|2(?:\.xpre7|00PleaseBot|Bone|locosbot)|3(?:60Spider|3W1bot)|4(?:04(?: C|c)heck|(?:40network|algeria)|SeoHunt)|50\.nu|80legs)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%A(?:6-Indexer|BCdatos BotLink|D(?:Bot\/9\.0|SARobot|mantX)|ESOP_com_Spider|I(?:BOT|TCSRobot\/)|MZNKAssocBot|S(?:PSeek|pider\/)|TN_Worldwide|URESYS|b(?:acho|o(?:nti|u(?:ndex|tUsBot))|rave Spider)|c(?:c(?:elobot|oona-AI-Agent)|o(?:iRobot|onBot\/)|unetix)|d(?:beat bot|dThis\.com|normCrawler|oSpeaker|vBot\/)|h(?:oy! The|refs ?Bot)|irmail|l(?:ex(?:a|i) ?bot|ibaba|phaBot\/)|m(?:agit\.COM|fibibot|igo\/(?:6[2-9]|[789]\d)\.)|n(?:DOSid|alyzer|d(?:ersPinkBot|roidDownloadManager)|emone|onymouse|swerBus|t(?:Bot\/|hill|ivirXP08|uris Agent)|yEvent|zwersCrawl)|p(?:ercite|port(Worm)?|p(?:Engine|leNewsBot|lebot))|qua_Products\/1\.1|r(?:a(?:Bot|chmo|chnoidea|meda|ne(?:a|o))|chitextSpider|ellis|gus|ielisBot|t-Online|thurHoaro)|s(?:k(?:Quickly|TB)|p(?:eratus|iegel)bot|tute)|t(?:las|omz)|u(?:disto Crawler|tomattic Analytics Crawler|tonomy))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%B(?:-l-i-t-z-B-O-T|CKLINKS|D(?:Cbot|Fetch)|L(?:EX Bot|P_bbot)|O(?:T for JCE|TW Spider)|PImageWalker|Spider\/1.0 libwww-perl\/0\.40\/1\.1|UbiNG|a(?:balooSpider|ck(?:DoorBot\/|Rub\/\.\/|Web|link(?:-Ceck|Crawler))|d-Neighborhood|i(?:du|t & Tackle)|ndit|rkrowler|tchFTP|zQux)|e(?:(?:bop|come|etle)Bot|gunAdvertising)|i(?:g(?: Brother\/|Bozz|CliqueBOT|foot)|mbot|trix|z(?:[Bb]ot0|wikiBot))|l(?:ack(?:(.*)? Hole\/|Widow\/|board Safeassign)|ekko Bot|inkaCrawler|o(?:g(?:Pulse|Search|lovin|sNowBot|trottr)|wFish\/))|o(?:a:(?:rdReader Favicon Fetcher|tersbook.com)|okmark search tool\/|t(?: mailto:craftbot|\.AraTurka\.com\/|ALot\/|OnParade|RightHere\/|Robin))|r(?:a(?:in(?:bruBot|tree-Webhooks)|n(?:ch-Passthrough|dProtect bot))|o(?:kenLinkCheck\.com|wser(?:SpyBot|shots))|uinBot)|u(?:ckyOHare|ddy|iltBotTough\/|llseye\/|nnySlippers\/|siness(?:Bot|Seek\.biz|jet)|tterfly|zz(?:Sumo|bot))|ytespider)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%C(?:-T bot|ACTVS Chemistry Spider|(C)?Bot\/|CGCrawl|ERT\.at-Statistics-Survey|ISPA V|J(?:\.com crawler|NetworkQuality)|MS (?:Crawler|Spider)|O(?:IBotParser|MODOSpider)|R(?:AZYWEBCRAWLER|IM Crawler)|SS Certificate Spider|XL-FatAssANT|a(?:kePHP|lif|montSpider|psuleChecker|re(?:erBot|tNail)|stabot|tchBot\/)|e(?:gbfeieh\/|r(?:berian|finfo))|h(?:a(?:ngeDetection\/|rlotte)|e(?:ck(?:-Domains\.com bot|(-)?Host|MarkNetwork|bot\/x\.xx LWP\/|sem)|eseBot\/|rryPicker)|i(?:naClaw\/|stCrawler\.com))|i(?:ndooSpider|pinetBot|rrusExplorer)|l(?:arity(Daily)?Bot|i(?:ckagy Intelligence Bot|gooRobot|mate Change Spider|qzbot\/)|o(?:sure Compiler Service|ud(?: mapping|Flare-AlwaysOnline|ServerMarketSpider|flare-Smart-Transit|inary)))|o(?:gentbot|inCornerBot|l(?:dFusion|lective)|m(?:mon(?:Crawler Node|s-HttpClient)|odo|p(?:SpyBot\/|any(?: News Search engine|book)|uter_and_Automation_Research_Institute_Crawler))|n(?:t(?:acts Crawler|entScan|extAd Bot)|vera(MultiMedia)?Crawler)|olBot|p(?:ernic\/|ier|perEgg|yRightCheck\/)|rpusCrawler|staCider|uponBot|vario|wbot)|r(?:awl(?:Convera|ForMe|Wave|er(?:4j|ra))|escent(?: Internet ToolPak|\/)|o(?:cCrawler|wsnest))|u(?:kBot|rious George|sto\/)|yber(?:Patrol SiteCat Webbot|Spyder\/))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%D(?:AWINCI ANTIPLAG|(?:BL|L2)?Bot\/|(?:IY-SEO|KIMRep|(?:F|ealGates|ex Media|ialogSearch\.com) |iamond|ocfu|ragon|wnld)Bot|(?:CP|ER-|II|NA|azoo|iff|igincore |iscord)bot|I(?:E-KRAEHE|SCo(?: Pump|\/|Finder\/)|7SP2)|M-Search|NS(?:-(?:Digger|Tools)|OJ3jx7bf|Pod(?: crawler|-reporting))|Search|TAagent|W(?:CP|DS-crawler)|a(?:r(?:cyRipper|reBoost)|ta(?:Cha0s|Fountains|parkSearch)|um(oa\/)?)|e(?:ad Link Checker|epIndex|mon|nsity|pSpid|sertRealm\.com|uSu|vil|web\/)|i(?:e Blinde Kuh|gg(?: Deeper|er)|ttoSpyder\/)|o(?:m(?:ain(?: Re-Animator Bot|Appender|DB|(?:DB\.net Meta|Macro|SONO|Sigma|Tuno)Crawler|StatsBot)|nutch-Bot\/Nutch-)|t(?: TK - spider|com-Monitor bot)|w(?: Jones Searchbot|nload(?: De(?:mon\/|vil)| Wonder|Bot\/|er)))|r(?:ecombot|ip))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%E(?:ARTHCOM|CCP|M(?:C Spider|PAS_ROBOT)|NLLE bot|S\.NET|TI SEO bot|ZResult|as(?:ouSpider|y(?:-Thumb|Bib AutoCite|DL))|biNess|co-Portal Spider|disterBot|irGrabber\/|lectricMonk|m(?:ail(?:Collector|MarketingRobot|Siphon|Wolf)\/|bedly)|n(?:finBot|igmaBot\/|vironmental Sustainability Spider)|roCrawler\/|sribot\/|u(?:le-Robot|r(?:ipB|ob)ot)|v(?:e(?:nt(?:GuruBot\/|Machine)|ryoneSocialBot)|idon|liya Celebi|o Bot v|rinid)|x(?:B Language Crawler|a(?:bot(-Images)?|ctSe(?:arch|ek)|lead)|c(?:el|hangleBot)|p(?:er(?:ibot|tSearchSpider)|loratodo|ress WebPictures\/)|tractor)|yeNetIE\/|zooms)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%F(?:AST(?: bot|-)|DM_2|Fbot|Hscan|a(?:cebook(?: external hit|Bot)|irAd Client\/|lconsbot|raday|st(?:Bug|Crawler|Probe)|(?:t|u)Bot|v(?:Org|collector|eeo)|xobot)|e(?:astieBot|lixIDE\/|tch(-Guess?)|ver)|i(?:leHound|nd(?:ABusinessThat\.|exa Crawler|xbot\/)|reball|sh-Search-Robot\/)|l(?:a(?:ming(?: AttackBot\/|o_SearchEngine)|shGet\/)|i(?:ckBot|ghtDeckReportsBot\/|pboard(?:Bot|(Browser)?Proxy))|ocke bot|uffy the spider)|o(?:llowSite Bot|o(?:bot\/|ooo_Web_Video_Crawl|)|rest Conservation Spider|undSeoTool)|r(?:a(?:ncis|nklin_Locator)|ee(?:Find|WebMonitoring SiteChecker|_Link Build|crawl\/)|ontPage\/)|u(?:ckOff|erza|nnel(?:Web|back)|sionBot)|y(?:berSpider|rebot))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%G(?:AChecker|C3pro|IDBot|LBot|OFORITBOT|SLFbot|Tmetrix|VC  WEB crawler|a(?:isbot\/|laxyBot|rlikCrawler|torWarmer)|e(?:liyooBot|n(?:deranalyzer|ericBot-ax|ieo( Web filter)?|tleSource( Short URL Checker)?)|o(na)?Bot|sco|t(?:(Found)?Bot|LinkInfo|Proxi\.es-bot|Right\/|Smart|URL(?:\.rexx|Info)|Web!|intentCrawler))|i(?:ga(?:blastOpenSource|(mega\.)?bot)|mme(?:60|USA)bot|ngerCrawler|rafabot)|l(?:oomarBot|uten Free Crawler)|o(?:!Zilla\/|-(?:Ahead-Got-It\/|http-)|S(?:craper|potCheck|quared(-Status-Checker)?)|lem\/\d+\.\d\/|mezAgent|o(?:dzer|se)|rnKer|tSiteMonitor|zaikBot)|r(?:a(?:b(?:Net\/|ber)|fula\/|hambot|mmarly|peshot(?: Bot|Crawler))|o(?:mit\/|schoBot)|ubNG)|u(?:l(?:liver|per)|rujiBot))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%H(?:EADMasterSEO|MView\/|T(?:MLParser|TP(?:(?:-| )Header|-Tiny|Mon|TEST|_Compression_Test)|Track\/)|a(?:iloobot\/|mBot|ppyFunBot\/|rvest\/|tena |zel)|e(?:a(?:dDump|lthbot|rtRails(?:Bot|_Capture))|imdall|lpSpy|nryTheMiragoRobot|trixTools\.|urekabot)|o(?:lmes(Bot)?|me(?:Tags|rbot|town Spider Pro)|o(?:WWWer|tSuite crawler)|st(?:ItCheap|Tracker)|tzonu)|t(?:ml_Link_Validator_|tp(?:Components|Proxy|UrlConnection))|u(?:aweisymantecspider\/|b(?:Pages|Spot)|rdler)|y(?:bridBot|pe(r)?(?:Stat|Crawl|Zbozi)))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%I(?: Robot|CC-Crawler|D(?:Bot|whois)|E(?:AutoDiscovery|Check|Mozilla)|NGRID\/\d\.d\/|O(?:DC|neSearch\.bot)|P(?:2PhraseBot|AddressGuideBot|TCBOT)|RLbot|SC[_ ]Systems[_ ]iRc[_ ]Search|TI Spider|USA Browser|XEbot|c(?:eCat|onSurf)|deelaborPlagiaat|framely|l(?:Trovatore|seBot)|m(?:ag(?:e(?: (?:Stripper|Sucker)|(?:Engine|Fetcher))|ga(Bot)?)|p(?:lisenseBot|ressumscrawler))|n(?:Design|byBot|cyWincy|dy (Library)?|etURL|f(?:initeSweeps\.|luencebot|o(?:NaviRobot|Seek Robot|Spiders|Tekies|Wizards|ciousBot|rmant\/|seek Sidewinder))|nerpriseBot|stantSSL Browser|t(?:e(?:grity|lliseek|r(?:GET\/|NaetBoten|dose AntiSpamBot|net(?: Cruiser Robot| Ninja\/|Seer)))|raformant))|ps Agent|r(?:ia|okez\.|on33\/)|s(?:raeliSearch\/\d+\.\d/\d|sueCrawler|tellaBot\/))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%J(?:BH Agent|Factory|OC Web Spider|UST-CRAWLER|a(?:bse\.com Crawler|dynAveBot|karta|mes BOT|vaBee|yde crawler)|e(?:nny(?:Bot\/|Car)|t(?:Bot|Car\/|ty))|i(?:gsaw|keSpider)|ob(?: Roboter Spider|Kereso|boerse|diggerSpider|ot|rapido)|u(?:biiRobot\/|stView)|yxobot)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%K(?:AZ\.KZ_Bot|D(?: Bot|D-Explorer)|IT-Fireball\/\d+\.\d|O(?:CMOHABT|_Yappo_Robot)|a(?:kleBot|loogaBot|rneval-Bot|spersky|tipo\/\d+\.\d\/)|e(?:epRight|mvibot|njin[ .]Spider|y(?:CDN bot|word Density\/))|i(?:ckFire|lroy|monoLabs|ngbot)|nowledge\.com|o(?:libri|modiaBot)|r(?:OWLer|zana)|um(?:Kie|o)|wickbot|y(?:luka|oto-Crawler))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%L(?:\.webis|ABLEBot|DRbot\/|INK TRADE crawler|NSpiderguy|SSRocketCrawler|WP::Simple|XRbot|YT\.SR|a(?:belGrab\/\d+\.\d\/|pozzBot|serlikebot|yeredExtractor)|e(?:adingcourses|echFTP\/|ikibot|murWebCrawler|x(?:i|xe)Bot\/)|i(?:corne Image Snapshot|ferea|ghtspeedsystems|jit|ngu(?:a|ee )Bot|n(?:k(?:[_ ]Valet[_ ]Online|A(?:ider|larm|nalyser)|Crier\.|Ex(?:aminer|plore\.)|Lint|Market-Bot|Scan\/|Stats Bot|Tiger|Verifier1\.|Walker\/|dex Bot|edInBot|extractorPro\/|man|padBot)|qiaBot)|pperhey|teFinder|velapBot)|o(?:ad(?:Impact|TimeBot\/)|c(?:alcomBot|kerDomeMultimediaBot)|ngURL|ok(?:\.com|Seek\.com)|rkyll)|um(?:inateBot|pImageSearch))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%M(?:ARTINI|B-SiteCrawler|ETAG(?:OPHER\/|Spider)|F(?:C_Tear_Sample|GPagesBot)|I(?:A(?: Bot|Down )|Ixpc\/)|J12( )?bot|O(?:Mspider\/|QU ADV crawlers)|PDP-ALR-Search-Bot|Qbot|RCHROME|S(?: Cognitive Services|IECrawler\/|MOBOT|NPTC|R-ISRCCrawler|RBOT)|VAClient|a(?:Ma (?:C(?:aSpEr|yBer)|Xirio)|Sagool|c(?:Inroy Privacy Auditors|_Finder|kster)|g(?:(?:-N| n)et|iBot|pie-Crawler|us Bot)|il(?:\.Ru|Chimp)|jestic(?: 12| SEO)|ndrill|r(?:coPolo|kWatch|ketBrewBot)|ss Downloader\/|t(?:a[ .]Hari\/|rix)|ui Browser|vicanet|xPointCrawler)|e(?:MoNewsBot|anPath Bot|chanize|di(?:a(?:Fox\/x\.y\/|LBot|toolkitbot)|umbot)|gaIndex|lvil|r(?:g(?:adobot|eFlow-PageReader)|zScope\/)|ta(?:CommentBot|GeneratorCrawler|HeadersBot|Inspector|JobBot|URI|mojiCrawler|s(?:earch|pinner)))|get|i(?:aDev|cros(?:earch|oft[._]URL)|n(?:djet|erBot|iflux)|r(?:ago|ror)|s(?:sigua[ _]|ter )|x(?:Bot|rankBot))|kzilla|nogosearch|o(?:j(?:eekBot|olicious)|n(?:Tools\.|itori(?:ng|ty)|keyCrawl|oBot\/|ster)|odleBot\/|r(?:Mor TCP Spider|eover|akyPraceCzBot|cgiguy|feus (strikes again)?|ning Paper)|to(?:MinerBot|r\/\d+\.\d\/|ricerca-Robots\.txt-Checker))|p3Bot|u(?:ltiviewbot|scatFerret)|y(?: (?:Nutch Spider|User Agent|WinHTTP Connection)|-Application|A(?:gent|pp)|UserAgent|_WinHTTP_Connection))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%N(?:AMEPROTECT|C(?: Bot|SA_Mosaic)|E(?:C-MeshExplorer|WT)|G-Search|HSEWalker\/\d+\.\d\/|I(?:CErsPRO\/|ING)|L(?:Crawler|NZ_IAHarvester)|Pbot\/|TENTbot|a(?:il|jdi\.si|lezenCzBot|meOfAgent|tionalDirectory|v(?:erBot|issoBot|road\/))|e(?:arSite\/|kstbot|lian Pty Ltd - Spider|oScioCrawler|r(?:dByNature\.Bot|dy Bot)|t(?: Vampire\/|tAnts\/|Carta CyberPilot|Lyzer|M(?:echanic\/|ind-Minder|onitor)|N(?:ewsWire|ose)|ResearchServer|S(?:coop\/|helter|pider|print)|Track|Z(?:IP\/|ip(?:-Downloader|py))|craft|peak bot|s(?:eer|parker)|t(?:\.io|hrob-bot)|vibes|working4all)|u(?:mobBot|star|trinoAPI)|w(?:-Sogou-Spider|ShareCounts\.|UseAgent|lyso\.com|s(?:Blur \.|Gator|groupreporter_LinkCheck))|xtGenSearchBot)|i(?:gma\.ru|kto|mbleCrawler|nja|tro PDF Doaload)|map|o(?:mad-V\d\.|rton-Safeweb|tifixious)|u(?:esbyte|search Spider|tch|zzel)|ymesis)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%O(?:Gspider\/|LE Control v.\d.\d\/\d+\.\d|bjectsSearch|c(?:arinabot|cam\/\d+\.\d\/|elli|to(?:pus\/|ra_Beta))|dklBot|ffline[ -.][a-zA-Z]+\/|m(?:ea|ni(?:Explorer|pelagos|zensBot))|n(?:PageBot|etSzukaj|line Domain Tools|toSpider)|p(?:e(?:n(?: (?:Text Site Crawler|Web Analytics Bot)|CalaisSemanticProxy|HoseBot|IntelligenceData|VAS|WebSpider|bot\/\d+\.\d|di Bot|f(?:ind(?: data gather|\/)|osBot)|indexSpider|stat)|rabot\/)|pO|timiz(?:ationCrawler|er))|r(?:a(?:cle Ultra Search|ngeBot\/)|biter|g(?:Probe|byBot))|sObot|utfoxBot|wler)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%P(?:AD-bot\/|E(?:AR_HTTP_Request_class|ERbot)|GP-KA\/\d+\.\d\/|H(?:OTO CHECK|P[ _]version[ _] tracker)|INGOMETER|OE-Component-Client-HTTP|TST|WBot|a(?:ckRat|ge(?: (?:Analyzer|Valet)|BitesHyperBot|Grabber\/|Peeker|bull|s(?:Inventory Bot|peed))|jaczek|n(?:deo Bot|op(?:ta|y Bot))|p(?:a Foto\/|erLiBot)|rchBot|t(?:ric|webbot))|core-HTTP|e(?:arltrees|e(?:kBot|plo Screenshot Bot|powbot|w)|r(?:Man\/|colateCrawler|formance)|te-Spider)|h(?:antom(?:\.js|JS)|pDig)|i(?:-Monster|ltdownMan|mptrain|ng(?:Spot|oscope)|oneer|plBot|ta |xray-Seeker|zilla)|l(?:antyNet|oetz|u(?:kkie|rkBot))|o(?:cke(?:tParser|y)|dcastPartyBot|irot|lyBot|mpos|o(o)?dle_predictor|p(?:Screen Bot|dexter)|r(?:kbun|t(?: Monitor check service|_Huron_Labs|alJuice))|stPost|werMapper Crawler)|r(?:erender|i(?:ceonomics|ncetonbot|tTorrent|va(?:cyAwareBot\/|teSearch))|log|o(?:Cog(SEO)?Bot\/|PowerBot\/|WebWalker\/|ductoDownloadUrlBot|found scrapyproject|ject 25499|m(?:icxic|otion_Tools)|topage|xad))|u(?:_iN|lsepoint|mp|rebot)|y(?:Query|thon-urllib\/|wikibot))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%Q(?:irina|seero|u(?:alidator|e(?:pasaCreep|ry(?:N Metasearch|SeekerSpider)|ster)|ickSproutBot\.|ora)|w(?:antify|eeryBot))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%R(?:6(?: bot|_CommentReader)|A(?:DaR-Bot\/|MPyBot)|BSE Spider|E(?:Dbot|L_Link_Checker_Lite)|MA\/\d+\.\d|OR Sitemap Generator|X Bar|a(?:dia(?:n6|tion Retriever \d+\.\d\/)|n(?:dom|k(?:Active Bot|Flex\.|SonicSiteAuditor|ing[ -]|urBot)|valBot)|ve(?:lry\.|nCrawler)|wi)|e(?:Get\/\d|a(?:dability|lDownload\/|per)|belMouse|corder|d(?:esScrapy|irect)|ederForMac|git|lateIQ Crawler|poMonkey\/|s(?:earchBot|ponseCodeTest|tSharp|ume Robot\/)|trevoPageAnalyzer)|i(?:ddler|val )|o(?:bo(?:Crawl|sourcer|t(?: du CRIM|s(?:Checker|_Tester))|zilla)|ger Bot|nzoobot|verbot\/)|u(?:by |fusBot|k(?:iCrawler|ky-Roboter)|net-Research-Crawler)|yzeCrawler)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%S(?:A(?:I Crawler|NSARN)|B(?:A Research bot|Ider|L-BOT|Search)|CFCrawler|EO(?: Browser|Centro|Dat|ENG(?:Bot|WorldBot\/)|diver|kicks-Robot|ly(?:ticsCrawler|zer)|stats)|KB Kontur bot|M(?:PU|RF|TBot|UrlExpander)|NAPSHOT|OLOFIELD bot|PEng|S(?:L(?: Labs|-Crawler|Bot)|M Agent)|TINGbot|VD_TXT|WEBot\/|a(?:fe(?:Ads\.xyz bot|DNS(?: search b|B)ot|tyNet Robot)|lesIntelligent|n(?:dCrawler|szBot)|uceNAO)|c(?:arlett|hmozillav|o(?:o(?:p|ter)|p(?:e \\(Mars\+\\)|ia crawler)|ut)|r(?:apy|een(?:ShotService|erBot Crawler)|ew-Ball|ubby))|e(?:arch(?:-10|17Bot|Sight|mee!|metricsBot|spider)|c(?:retBrowser|urityResearchBot)|ekbot|m(?:a(?:ger|nti(?:c(?: Health Web Crawler|ScholarBot)|fire))|rush)|n(?:rigan\/xxxxxx|sis(\.com\.au)? Web Crawler|tiBot)|o(?: Servis|Check|(?:Profiler |Stack)Bot|bility|logies|pultContentAnalyzer|territory\.)|rv(?:er Density|iceUptime\.robot|is)|toozbot)|grunt|h(?:a(?:gSeeker|reaholicbot)|im-|o(?:p(?:Wiki|pimon)|rtLinkTranslate|wyouBot)|unixBot)|i(?:deWinder|lverReader|mple[A-Z]|phon|te(?: Valet|-Shot|24x7|Analyze|Bar|Condor|Explorer|Guardian|Intel\.net Bot|LockSpider|Probe|Snagger\/|SpeedBot|Spider|Truth|Winder|XY Webmaster tools|domain-Bot|improve|liner|luxbot|shooter))|k(?:routz|ypeUriPreview)|l(?:ackbot|ySearch)|ma(?:bblerBot|rtDownload\/|rtLinksAddon)|n(?:4keVisor|a(?:ke|pbot|ppy|rfer)|ipebot|oop(?:er\/|y))|o(?:l(?:bot\/|omonoBot)|mePerlRobot|rtSite|sospider)|p(?:a(?:ce(?:Bison|bug)|nkBot\/)|eed(?:-Meter|y( )?Spider)|i(?:Dir\.|ce M5460|der(?: Indexer|Ling|Man Mozilla|_Monkey)|nn(?:3r|e))|latSearch|o(?:ck Crawler|keSpider)|rinklr|u(?:hexBot|rlBot|tnikBot)|yNet)|q(?:ui(?:d(?:-Prefetch|ClamAV_Redirector)|gglebotBot)|worm(?: i686-pc-linux|\/))|t(?:a(?:ckRambler|s(?:hBot|bot\/)|t(?:astico|oolsBot|usCake))|e(?:eler|phan Kopp bot)|itcherBot|or(?:m-crawler|ygizeBot)|r(?:atagems|ipper|okebot)|u(?:dioFACA|mbleUpon))|u(?:ck(er)?|fog|p(?:er(?: Monitoring|Bot\/|HTTP\/|PagesUrlVerifyBot|arama)|ports gzip encoding|ybot)|r(?:centroBot|dotlyBot\/|fbot\/|phace|vey))|wi(?:ssSearch|teScraper)|y(?:golBot|mfony(?: Spider|2)|n(?:HttpClient-Built|oBot|tryx)|s(?:omos|tem\.Random))|zukacz\/)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%T(?:0PHackTeam|A SEO Crawler|HIS PC WAS TAGGED BY|TD-Content|WMBot|a(?:goobot|lkTalk|r(?:antula|inga|motBot))|e(?:amSpeak bot|chnoratibot|eRaidBot|le(?:gramBot|leport\/|soft\/)|r(?:adex Mapper|rawizBot)|st(?: Certificate Info|Crawler|omatobot)|trahedron)|h(?:e(?:[ .]Intraformant\/|FreeDictionary|Nomad\/)|i(?:ng(?:Fetcher|link ImageBot)|sIsOurYear_Linkchecker)|umb(?:Shots-Bot|Sniper|bnail\.CZ|shots))|i(?:ghtTwatBot\/|n(?: Eye|y)|pTop|tan\/)|k(?:Bot\/|ensaku)|o(?:ata dragostea mea|doExpertosBot|mTom places|ols4noobs\.|picbot|read-Crawler|u(?:Trix crawler|tiaoSpider)|weya(?:\.|bot))|r(?:aackr|identSpider|ue(?:Bot\/|_Robot\/))|u(?:rnitinBot|tor(?:GigBot|ial Crawler))|w(?:e(?:etm(?:emeBot|inster)|ngaBot)|i(?:celer|kle|ngly))|y(?:goBot|phoeus))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%U(?:2Bot|ASlinkChecker|CSD-Crawler\/|RL(?: Control\/|AppendBot|Checker|SS|(_)?Spider(_)?Pro\/|itor\.|y[ .]Warning\/)|TSE|XCrawlerBot|dmSearch|ltraseek|n(?:i(?:corn|sterBot\/|tek UniEngine)|windFetchor\/)|p(?:downerbot|flow|timeDog|timeRobot)|rl(?:Dispatcher|Trends|(file)?bot|stat))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%V(?:CI(?: WebViewer|\/)|PNGate|S(?:Agent|B-TUO)|YU2|a(?:cuum|dixBot|gabondo|l(?:et|kyrie\/)|mpire)|e(?:Bot|dma|g(?:eBot|i bot)|oozbot)|i(?:deoSurf_bot|gLink|rusdie crawler|sbot)|o(?:i(?:dEYE\/|laBot)|r(?:boss Web Crawler|tex)))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%W(?:3CRobot|ASALive-Bot|BSearchBot\/|EP(?:A|P_Search)|GETbot|ISE(Nut)?bot|MCAI_robot|OW32|P(: Engine|Scan)|URFL ImageEngine|WW(?:[ -]Collector(?:\/|-E)|-Mechanize|OFFLE\/|Wanderer |easel)|a(?:ppalyzer|tchMouse)|bSrch|e(?:CrawlForThePeace|LikeLinks|SEE|ViKa|b(?:[ .]Image[ .]Collector| Sucker\/|-(?:Monitoring|sniffer)|A(?:lta Crawler|uto\/)|Bandit\/|C(?:-I.com|apture \d|o(?:okies|p(?:ier\/|y)|rp)|rawler)|D(?:ataCentreBot|oc)|E(?:MailExtrac|nhancer\/)|F(?:e(?:rret|tch)\/|indBot|uck)|G(?:ather|o )|I(?:mages|ndex)|L(?:eacher|inker)\/|Moose\/|NL|Pictures|R(?:ankSpider|eaper\/)|S(?:auger\/|earch|ite|pider|tripper\/)|T(?:arantula|humbnail)|V(?:ac\/|iewer|uln(?:Crawl|Scan))|W(?:a(?:lker|tch)\/|hacker\/)|ZIP\/|a(?:rooBot|uskunft)|bot|clipping|masterWorld|navigator|s(?:hot|ite(?:[ .]Quester| eXtractor)\/|napr|quash|ter[ .])|thumb)|lls_Search_II)|h(?:a(?:cker|t(?:Web|chaBot))|i(?:bse|zBang)|o(?:\.is Bot|Where Robot|is(?:mindbot|websitebot))|y(?:NoPadlock|nder))|i(?:dow\/|ki(?:Bot|Do)|l(?:d Ferret Web Hopper|l(?:ow Internet Crawler|yBot))|n(?:HttpRequest Bot-Trap-Test|WebBot|iFighter)|seWire)|o(?:TBoT|ko|mlpeFactory|nder|oRank|r(?:d(?:ChampBot|Press\.com bots)|ld(?: web heritage|BrewBot)|mlyBot)|tbox))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%X(?:GET\/|ING-contenttabreceiver|ML Sitemaps Generator|YZBot|a(?:ldon[ _]WebSpider|xisSemanticsClassifier)|en(?:u(`s)?[ _]Link[ _]Sleuth)|m(?:arksFetch|lSitemapGenerator)|o(?:mbot|viBot)|unBot)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%Y(?:!TunnelPro|OOBI\.de bot|(?:R|Y)Spider|a(?:anb|dowsCrawler|hooSeeker|manaLab-bot|ndeG|nga |saklibot\/)|e(?:l(?:lowLabTools|pbot)|supBot\/|ti\/)|i(?:eldbot|oopBot|souSpider)|o(?:-yo|daoBot|leo |tta(?:(Shopping_)?Bot|aMonitor)|udaoBot|wedoBot))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%Z(?:-Add Link Checker|IPCodeBuyBot|atka|e(?:albot|erchBot|ller|manta|us(?: Link Scout|\/|_))|ip(?:Commander|ppBot)|mEu|najdzFoto|o(?:mbiebot|o(?:kabot|m(?:Bot|Info bot)))|u(?:hause\\(ARexx\\)|mBot)|yBorg\/)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%a(?:3logics|b(?:by|o(?:nti\.|utthedomain))|c(?:he |ontbot|rylicapps)|d(?:beat|ressendeutschland\.de)|ffiliatewindow|gentslug|h-ha|i(?:HitBot|ohttp|pbot)|kula|l(?:e(?:rtra|exa)|maden|ternatehistory\.|yze\.)|m(?:agit|ericanfoodbloggers|ibot|jCrawler\/)|ntibot|ppie|r(?:achnode|chive\.|genfybot|ia2)|s(?:afaweb\.|terias\/|ynchttp)|t(?:asift\.|tach)|u(?:skunftbot|tocite)|weber\.|ylienbot)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%b(?:2w\/\d+\.\d\/|a(?:cklink-check\.|nglalink|ypup)|e(?:h1001|slist\.nl|taBot)|i(?:bnum|glotron|nlar|t(?:lybot|vore\.)|xocrawler|z_Directory)|l(?:\.uk_lddc_bot|ogbeat\.nl|u(?:brry|efish))|nf\.fr_bot|o(?:ardreader\.com|itho(\.)?com|rg-bot|t(?:-pge\.chlooe\.|\.wsowner\.|mobi))|r(?:andonmedia|ightlocal\.)|tbot|umblebee)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%c(?:IeNcIaFiCcIoN|arsopict\.|cubee|g-eye|h(?:arlieapp\.|eck(?:-domains\.|gzipcompression\.|link)|kme)|i(?:tenikbot|ty(?:grid\.|review))|l(?:assbot|ips |sHTTP)|m(?:cm|sworldmap\.)|o(?:ccoc|lbert|m(?:Agent|bine\/\d+\.\d\/)|n(?:ceptbot\/\d+\.\d\/|t(?:actbigdatafr|e(?:ntDetection|xtadbot)|xbot\/)|vera)|pyright |smos\/)|rawl(?:er(?: (?:National Library|for netopian))|ingpolicy)|u(?:r(?:ata\.|b )|tbot\.|whois)|xense\.|ybo)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%d(?:ata(?:gnionbot|minr\.com|provider)|e(?:adlinkchecker|ep(?:crawl|searchnine)|voll)|i(?:enstspider|g(?:g\.com|italpebble)|s(?:avowfiles\.|coverybot\/|squs\.))|j(?:-research|bot)|l(?:cbot|vr\.)|o(?:coloc|mainsbot|tSemantic|wn(?:foreveryoneorjustme|notifier))|r(?:agonfly|rkpi\.|upact)|u(?:baiindex|mbot\/))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%e(?:-SocietyRobot|C(?:a(?:irn-Grabber|tch\/)|ommerceBot)|S(?:tyle|yndiCat )|asycron|bingbong|c2linkfinder|l(?:efent|finbot)|m(?:efgebot\/|udesc\.)|n(?:ergyexperts\.|volk)|quellaurlbot|sther|toolsbot|uroparchive|v(?:c-batch|ent(?:Bot|tax))|x(?:if-search|plorersearch\/))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%f(:a(?:ctbot|irshare|ntomas|stbot crawler)|e(?:eltiptop|mtosearch\.)|i(?:do\/\d+\.\d Harvest|n(?:bot|d(?:link|thatfile))|rmilybot)|l(?:atlandbot|u(?:ffy|nky)|ynxapp)|o(?:cusbot|r(?:Each|ensiq)|uineur)|reelinkexplorerbot|tt2\.com)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%g(?:2reader-bot|a(?:narvisitas|zz)|creep\/\d+\.\d\/|e(?:ek-tools|neral\.useragent\.override|nevabot|staltIconoclast|t(?:prismatic|request))|hostery|ipo-crawler|lindahl-cocrawler|o(?:crawl|liatspider|nzo|o(?:blog|d(?:barber|reads)\.)|squared-thumbnailer|tit)|r(?:iffon|ouphigh|ub(?:-client|\/\d))|umgum\.|vfs)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%h(?:a(?:cker|wkReader)|e(?:llo world|ritrix)|grepurl|l(?:_ftien_spider|edejLevne|oader\/)|o(?:sterstats\.|tpage\.|uzzbot)|t(?:dig|rix|tp(?:-kit|_sample|hr|lib\/|s(?:check|sites_power)|unit))|umanlinks\/)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%i(?: am a stego|686-pc-linux\/\d+\.\d|Cjobs|HWebChecker|ZSearch\.|a(?:_archiver|jaBot)|c(?:at\.co\.th|hiro|sbot)|dmarch|gdeSpyder|ltrovatore-setaccio|m(?:age\.kapsi\.net|mediatenet thumbnails|port\.io)|n(?:agist\.com url crawler|bound|dex-of-tv\.|f(?:egy|o(?:bot|helfer|mine\.ucr\.edu))|oreader\.|pwrd|t(?:e(?:gr(?:ishield\.|omedb)|lium_bot|rnet(?:Vista|_archive))|raVnews))|p(?:rospect\.|s-agent|ts\.|v6-test)|qdb|s(?:itup|kanie)|t2media-domain)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%j(?:a(?:gajam\.|nforman\.|ribot)|o(?:hnhew crawler|oble\.)|pg-newsbot|u(?:mpstation\/|stpicsplease\.))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%k(?:a(?:s(?:parek|taneta)|zbtbot)|inshoo |now(?:knot\.|ledge |s )|ouio|ul(?:oko-bot|turarw))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%l(?:a(?:nshanbot|rbin\/)|e(?:adcrunch\.|onosa)|ftp|i(?:b(?:Web(\/)?clsHTTP|rabot)|kse|n(?:cobot|exsystems|guatools|k(?:Check|_thumbnailer|(apedia)?bot|fluence|is|looker\/|peek|ulator|within\.))|stonATccDOTgatechDOTedu\/|vedoor ScreenShot)|mspider|o(?:ad-time|oksystems)|t(?:bot\/|x71)|u(?:cideer\.|fsbot)|wp-(trivial\/)?)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%m(?:Shots|a(?:bontland|csflowers\.|ke\.myUrl|nzama\.|pping|r(?:ket(?:ing|wire\.)|vininfoseek)|s(?:hable\.|scan))|e(?:dia(?:rithmics\.|words bot)|ltwater\.|moryBot\/|nv\.com|t(?:a(?:cdn|data-service|ger2)|roguide\.))|fibot|i(?:n(?:dUpBot|iRank)|tambo\.|va\.com)|lbot|o(?:at\.com|b(?:a-crawler|ileOK)|g(?:et\/|imogi)|n(?:itis|tastic)|vistar|wser|zDex)|u(?:ckrack\.|lticrawler|s(?:obot|texist\.))|y(?:-robot|crawler))|(?<![Ss]ezna)mbot%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%n(?:a(?:gios|ver\/)|bertaupete95|e(?:t(?:Estate (NE )?Crawler|k6 crawler)|w(?:est\.exe|s(?: bot \/|me|paper)))|i(?:cebot|ki-bot|neconnections)|lpproject|o(?:de[\-s]|more404\.|tifyninja|wblogs\.|xtrumbot)|rsbot|u(?:bilosoft\.|hk)|worm)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%o(?:Bot\/\d|e(?:bot|gp)|iqBot|k(?:http|u-taka-lab-bot)|mgili|nline(?: link validator|-webceo-bot)|odlebot\.|pendi\.|utbrain|w(?:lin\.|nCloud))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%p(?:a(?:ge(?: scorer|_verifier)|nscient\.|rsijoo|vuk\/)|cBrowser\/|dffillerbot|eerindex|hp(?:crawl|servermon)|i(?:peLiner|r(?:ate|st))|laNETWORK|m(?:afind|ODP link checker)|o(?:cketcasts|d(?:bean\.|directory\.|paradise\.)|st(?:ano|rank))|r(?:-cy\.ru|agmaMx|ess(?:people|rush)\.|o(?:bethenet|cess|found\.|spectb2b|ximic))|s(?:bot(?: test|-page|\/)|ycheclone)|ushcrew\.|y(?:spider|thon-requests))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%q(?:ingdao bieshu chushou|uickobot|want\.)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%r(?:4Bot|a(?:nscoder|tup\.)|cdtokyo\.|e(?:ader\.aol\.com|d(?:back|ditbot)|plaz\.|triever)|o(?:b(?:ot(?:@monkia\.com\.tw|o)|schecker)|ot|swellspringcatalog)|wth-aachen)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%s(?:c(?:an(?:bot|ner)|hibstedsokbot|our|r(?:apy-redis|ipt injection|utiny))|e(?:arch(?:-photo\.info spider|\.KumKie\.com|\.ch|preview\/)|curity (?:analyser|scan)|e(?:gnifybot|k-crawler|s\.co|xie\.)|m(?:antic(?:-visions\.|bot|discovery|juice)|iocast\.)|nsis|o(?:-(?:audit-check-bot|nastroj)|chat\.)|plinkbot|r(?:pstatbot|vernfo\.)|tcronjob|xsearcher)|g-Orbiter|h(?:arpr\.|elob|opping\.com research|rinktheweb|ybunnie-engine)|i(?:deqik\.|msalabim|strix|te(?:check\.internetseer|lock\.com|quest|xy))|sky(?:grid|rock)\.|lider|mart\.apnoti\.|n(?:a(?:-|cktory)|iptracker|prtz)|o(?:cialbm_bot|fthub\.|gou |hu-search|lofield\.|otle\/)|p(?:_auditbot|a(?:mmer|nner\/|ziodati)|ecial_archiver|ider\.asp \/|o(?:ofedhost\.onlinescanner|rtspyder\.)|r(?:ay-can|oose)|y(?:der\d\.microsys\.|onweb))|ql injection|t(?:a(?:ff|rt(?:\.exe|mebot)|t(?:crawler|dom\.ru))|orebot\.|q_bot|r(?:ap wrench bot|esstest|uts-pwn)|udylib bot)|u(?:ch(?:en|knecht)|ggybot|kibot_heritrix\/|mmify|reseeker|zuran\/)|ygol)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%t(?:6labs|AkeOut\/|a(?:boola|gSeoBot|ptubot)|bot-nutch|e(?:lnet0|mnos\.|st)|h(?:e(?:internetrules|oldreader)|ie(?:f|ves)|umbshots)|i(?:gerbot|mboBot)|ldstat|o(?:Crawl(\/)?UrlDispatcher|p(?:bloglog\.|icblogs|ster)|quo\.es|uche)|r(?:endictionbot|ivial|o(?:ovziBot|v(?:ator\.|itBot))|uwoGPS)|uringos\/|we(?:etedtimes|nga))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%u(?:12Bot\/|MBot|bermetrics|classify\.|ipbot|nchaos_crawler|pdated|rl(?:ck\/\d|fan-bot|resolver)|securio\.)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%v(?:BSEO(?:\/|_)|URL Online|e(?:bidoobot|rs(?:ellie\.|us crawler))|i(?:sionutils|talbox1@hotmail)|kShare|o(?:ltron|yager))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%w(?:3(?:af|dt\.net)|angling|eb(?:-capture|Mirror|Pluck|c(?:eo\.|ollage|rawl\.net)|eaver\.|i(?:natorbot|s )|kit2png|layers\/|mastercoffee|numbrFetcher|reaper|screenie|sitepulse|walk\/)|f(?:84|_crawler)|i(?:bbitz\.|kiwix-bot|red-digital-newsbot\/|se-guys|sponbot|thknown\.)|khtmlto|mtips\.|o(?:nderbot\/|obot|riobot)|pspydr\.|s(?:Analyzer\/|check)|wscheck.com|ww(?:\.(?:adressendeutschland|express-soft|freeloader|iir|osaicbt|otway|vinn\.com)\.|ster))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%x(?:100Bot\/|28-job-bot|USAx|ing\.|irq|pymep)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%y(?:acy|e(?:lpspider|s\/)|napse|o(?:o(?:gliFetchAgent|zBot)|ur(?:-search-bot|eputation\.|ls)))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%z(?:eef\.|grab|itebot|ootycoon\.)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%(?i)(?:aip|biru|chitika|dnyz|s(?:eoeng|kim|quad)|tob|upicto|w(?:bsearch|ebalt|ise(nut)?))bot%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%(?i)(?:; widows |\.(?:getpebble\.com|net clr 1\\))|\\(auto shell spider\\)|\r|a(?:\s?href[=s]|d(?:d catalog|mantx)|lwaysonline|merica online browser|rtabus|udit)|b(?:abya discoverer|pimagewalker|ubing)|c(?:l(?:am antivirus|oudflare)|o(?:m(?:odo(-certificates-)?spider|patible(?: ; msie|-))|verscout)|python|ydia)|d(?:atabasedrivermysql|cs|iscoveryengine|le_spider|o(?:mainreanimator|tnetdotcom\.org)|ts agent)|e(?:m(?:ail extractor|bedly)|xtraxt)|f(?:isuna\.com|unwebproducts)|g(?:eezer|osospider|sa-crawler)|h(?:a(ckteam|nzoweb|rvest|vij)|ttrack|uaweisymantecspider)|i(?:carus6j|nfospider)|jplastiras\.com|l(?:a(?:nk slooth|rbin@unspecified)|egalx\.|inkdex\.comucidmedia)|m(?:iner|rie8pack|s(?:\s?frontpage|nbot\/(?:1|2\.0))|urzillo compatible)|n(?:ettrapport crawler|otconfigured)|offbyone|p(?:a(?:gepeeker;|lantir)|eoplepal|hpinfo\\(\\)|icsearch|o(?:e-component-client|wermarks)|uritysearch)|r(?:6_|assler|e(?:corded future|verseget\.com)|ssmicro\.com)|s(?:ecretsearchenginelabs|ite-shot\/|nappreviewbot|ocial-object-extractor|pamblockerutility|uperfeedr)|t(?:elesphore|uring machine|w(?:i(?:sted pagegetter|tt(?:erfeed|urly))))|u(?:nspecified\.mail|ser-agent: )|valueclick|w(?:ebwasher|or(?:dpress\/;|io\.com))|xedant human emulator)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%(?i)(?:(?:f(?:a(?:ng|vOrg|xo)|dse|eed(?:24|hub)|i(?:lan|le(?:boo|Hound)|map|nd|re(?:bat|download\/)|rs)|l(?:am|ash|exum|ickBot|icky|ip|uffy|y)|o(?:oky|rum|rv|st|to|un|xy\/1;)|r(?:iend|ontpage)|fu(?:ck|er|tile)|fyber))|^(?!.*(?:AppleWebKit\/|Android \d).*).*focus.*$)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%^(?:\}__|A(?:IBOT|lexibot)|B(?:ack(?:DoorBot|Web)|lack\.Hole)|Cogentbot|E(?:mailWolf|xabot)|HTTrack|I(?:lseBot|nfo(?:NaviRobot|Tekies)|ntelliseek|ria)|J(?:a(?:karta|va)|ustView|yxobot)|Keyword\.Density|L(?:inkScan\/|NSpiderguy)|M(?:a(?:g-?Net|rkWatch)|emo|i(?:crosoft.URL|rror)|ozilla(?:.*NEWT|\/3.Mozilla\/2\.01))|N(?:e(?:t(?:craft|Mechanic)|xtGenSearchBot)|G|ICErsPRO|i(?:ki-bot|mbleCrawler|nja))|O(?:penfind|utfoxBot)|P(?:HP version tracker|ockey|ump)|QueryN\.Metasearch|S(?:nake|paceBison|qworm)|URLy\.Warning|Vacuum|Web(?:.Image.Collector|clipping\.com|masterWorldForumBot)|Zyborg|l(?:ftp|ikse))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%^(?i)(?:=|\\\'(?!DuckDuckBot)|8484 boston project|a(?:dwords|lexibot|nonym(?:ization|ous)|sterias|tt(?:ach|ributor)|utoemailspider)|b(?:a(?:ckdoorbot|ndit|tchftp)|dfetch|i(?:gfoot|tlybot)|l(?:ackw|o(?:gsearchbot-martin|wfish))|ot(?: mailto:craftbot@yahoo.com|alot)|u(?:iltbottough|llseye|nnyslippers))|c(?:egbfeieh|h(?:e(?:esebot|rrypicker)|inaclaw)|o(?:llector|nte(?:ntsmartz|xtad)|p(?:ier|yrightcheck)|re-project\/|smos)|rescent|usto)|d(?:i(?:amond|g(?:ger|incore)|ibot|sco|ttospyder)|ownload|r(?:agonfly|ip)|umbbot)|e(?:asydl|bingbong|c(?:atch|ollector)|irgrabber|mail(?:\s?siphon|collector)|rocrawler|x(?:press|tractorpro)|yenetie)|f(?:l(?:ashget|unky)|o(?:obot|rum poster)|r(?:anklin|eshdownload|ontpage))|g(?:e(?:omaxenginebot|t(?:right|web!))|o(?:-ahead-got-it|!zilla|rnker|tit)|r(?:a(?:bnet|fula)|ub crawler))|h(?:arvest|eeii|loader|mview|ttpproxy|umanlinks)|i(?:gette|mage|n(?:dy library|ter(?:get|net (?:explorer|ninja)))|sc systems irc|ufw web)|j(?:ava 1\.|e(?:nnybot|tcar)|oc)|k(?:angen|e(?:njin|yword)|mccrew)|l(?:arbin|e(?:ech|xibot)|i(?:bweb\/clshttp|ghtningdownload|nk(?:extractorpro|walker))|wp)|m(?:a(?:c finder|ma c|ss|ta hari)|eta(?:products download express|uri)|i(?:crosoft data access|down|ixpc|ss(?:igua|ouri college browse)|ster)|o(?:get|rfeus|vable type|zilla(?:\s|\/(?:2|4.0(?:\\(|\+\\(compatible;\+))))|sie|ygetright)|n(?:360\/|a(?:meprotect|v(?:erbot_dloader|road))|e(?:arsite|t(?: vampire|ants|craft|spider|zip))|i(?:cerspro|tro)|pbot|utscrape\/)|o(?:ctopus|ffline|mniexplorer|penmaru)|p(?:a(?:gegrabber|ncient|pa|vuk)|cbrowser|hpcrawl|i(?:cscout|nterest)|lanetwork bot|ro(?:gram shareware|powerbot|webwalker)|s(?:bot\/|ycheclone)|ussycat|y(?:curl|thon-urllib))|r(?:am finder|e(?:aldownload|get|pomonkey|volt)|ma|obofox|ssimagesbot)|s(?:asquia|hareaza|i(?:phon|tesnagger)|l(?:edink|ysearch)|martdownload|n(?:apbot|oopy)|ogou|p(?:ankbot|anner|bot|iderman)|q webscanner|ta(?:mina|r downloader)|u(?:per(?: happy fun|bot|http)|r(?:fbot|veyagent)|zuran)|zukacz)|t(?:akeout|e(?:chrigybot|le(?:port|soft))|he(?: intraformant|nomad)|i(?:ghttwatbot|tan)|jvmultihttpgrabber|ocrawl\/urldispatcher|r(?:ackback|ue_robot)|u(?:ringos|rnitinbot)|w(?:engabot|iceler))|u(?:n(?:der the rainbow|windfetchor)|rly warning|ser|tilmind httpget)|v(?:adixbot|ci|oideye)|w(?:00t|e(?:b(?: (?:downloader|image collector|sucker)|auto|bandit|co(?:llage|pier)|e(?:mailextrac|nhancer)|f(?:etch|ilter)|go|leacher|miner|reaper|s(?:auger|ite(?: extractor| quester|-x suite)|t(?:er|ripper))|vac|whacker|zip)|lls search|p search)|get|i(?:dow|nnie poh)|ordpress|ww(?:-(?:collector-e|mechanize)|offle))|x(?:aldon|enu)|yebolbot|zeus)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%(?i)(?:<|>|’|\%0[AD0]|\%27|\%3[CE]|\%60|\d\/\*|#\!|\"|\n|^(?:.{0,5}|(?:\d+\.)?\d+)$)%', $this->BlockInfo['UA']), $Bot[0], $Bot[1]) ||
            $this->trigger(preg_match('%(?i)(?:win(?:(?: 9x|128|nt3)|dows (?:3|9[89]|2000|nt(?: (?:[0-57-9]\.|6\.[04-9]|1[1-9]\.|[2-9]\d\.|\d{3,}\.)| x\.y|;)|xp 5)))%', $this->BlockInfo['UA']), $Bot[0], $Bot[1])
        ) {
            $this->enactOptions('SuspectedBot:', $Options);
        }
        if (preg_match('%^17\.%', $this->BlockInfo['IPAddr'])) {
            if (preg_match('%\.applebot\.apple\.com$%', $this->CIDRAM['Hostname'])) {
                if (strpos($this->BlockInfo['UA'], 'Applebot') !== false) {
                    $this->bypass(strpos($this->BlockInfo['WhyReason'], $Bot[0]) !== false, 'Applebot Bypass 1');
                }
            }
        }
    }

    /** Signatures for end of life (EoL) browsers. */
    if ($this->Configuration['bobuam']['block_eol_browsers'] === 'yes') {
        $Browser = [
            $this->L10N->getString('bobuam_outdated_short'),
            $this->L10N->getString($this->Configuration['bobuam']['reason_browser']) ?: $this->Configuration['bobuam']['reason_browser'] ?: $this->L10N->getString('denied')
        ];
        if (
            preg_match('%(?:^.*(?<!googlebot\.com|google\.com|search\.msn\.com)$|^.*(?<=proxy))%', $this->CIDRAM['Hostname']) &&
            !(preg_match('%(?:msn|bing)bot|bingpreview|bing\.com%', $this->BlockInfo['UALC']) && ($this->hasProfile('Bypass flagged') || !isset($this->Stages['Tests:Enable'])))
        ) {
            $EOLChrome = $this->Configuration['bobuam']['chrome'] ?: (int)$this->CIDRAM['BOBUAM Token']['Chrome'];
            $EOLEdge = $this->Configuration['bobuam']['edge'] ?: (int)$this->CIDRAM['BOBUAM Token']['Edge'];
            $EOLFirefox = $this->Configuration['bobuam']['firefox'] ?: (int)$this->CIDRAM['BOBUAM Token']['Firefox'];
            $EOLFirefoxESR = $this->Configuration['bobuam']['firefox_esr'] ?: (int)$this->CIDRAM['BOBUAM Token']['Firefox ESR'];
            $EOLSafari = $this->Configuration['bobuam']['safari'] ?: (int)$this->CIDRAM['BOBUAM Token']['Safari'];
            if (
                $Chromium = preg_match('%^(?i)(?!.*edg(?:a|e|ios)\/)(?!.* build\/)(?!.* Favicon).*chrom(?:e|ium)\/(\d+)\.\d+.*$%', $this->BlockInfo['UA'], $rebt) ||
                $Chromium = preg_match('%^(?i)(?=.*android)(?!.* Favicon).*chrom(?:e|ium)\/(\d+)\.\d+.*$%', $this->BlockInfo['UA'], $rebt)
            ) {
                $TokenChrome = (int)$rebt[1];
                if ($this->trigger(($TokenChrome < $EOLChrome), $Browser[0] . ' (C)', $Browser[1])) {
                    $this->enactOptions('Chrome:', $Options);
                }
            }
            if (preg_match('%^(?=.*Mozilla\/)(?i).*Edg(?:a|e|ios)?\/(\d+)\.\d+.*$%', $this->BlockInfo['UA'], $rebt)) {
                $TokenEdge = (int)$rebt[1];
                if ($this->trigger(($TokenEdge < $EOLEdge), $Browser[0] . ' (E)', $Browser[1])) {
                    $this->enactOptions('Edge:', $Options);
                }
            }
            if (preg_match('%(?!.*SeaMonkey).*Firefox\/(\d+)\.\d+%', $this->BlockInfo['UA'], $rebt)) {
                $rebt = (int)$rebt[1];
                if ($this->trigger((($rebt < $EOLFirefox) && ($rebt !== $EOLFirefoxESR)), $Browser[0] . ' (F)', $Browser[1])) {
                    $this->enactOptions('Firefox:', $Options);
                }
            }
            if (preg_match('%^(?=.*Safari\/)(?!.*(?:(?:Kindle|DuckDuckGo| Build)\/|; wv\\)).*)(?i).*version\/(\d+).*$%', $this->BlockInfo['UA'], $rebt)) {
                $rebt = (int)$rebt[1];
                if ($this->trigger(($rebt < $EOLSafari), $Browser[0] . ' (S)', $Browser[1])) {
                    $this->enactOptions('Safari:', $Options);
                }
            }
            if ($this->trigger(!$Chromium && preg_match('%^(?i)(?!.*opera (?:mini\/|mobi).*)(?!.*(?:google(?:bot\/| web preview)|(android.*(?:version|samsungbrowser)\/)).*).*(?: Edge\/(?:(?:\d|1[01]|1(?:2\.(?:[02-9]|1(?:0[01346-9]|[1-9]))|3\.(?:[02-9]|1(?:0[0-46-9]|[1-9]))|4\.(?:[02-9]|1(?:4[0-24-9]|[0-35-9]))|5\.(?:0|1[0-4])))\.|[02-9])| Edg\/(?:\d|[0-6]\d)\.|msie\s?(?:\d|1[2-9]|[2-9]\d|\d{3,})\.|(?:netscape|mozilla\/(?:[0-3]\.|4\.0[24568]\s\[|4\.[578]|[7-9]\.|\d{2,}\.))|opera[\s\/](?:[0-8]\.|9\.[1-79]|bork-edition|1[01]\.|12\.(?:[02-9]|1[0-579])|1[3-9]\.|[2-9]\d\.|\d{3,}))%', $this->BlockInfo['UA']), $Browser[0] . ' (HC)', $Browser[1])) {
                $this->enactOptions('Other:', $Options);
            }
            if (preg_match('%^17\.%', $this->BlockInfo['IPAddr'])) {
                if (preg_match('%\.applebot\.apple\.com$%', $this->CIDRAM['Hostname'])) {
                    if (strpos($this->BlockInfo['UA'], 'Applebot') !== false) {
                        $this->bypass(strpos($this->BlockInfo['WhyReason'], $Browser[0]) !== false, 'Applebot Bypass 2');
                    }
                }
            }
        }
    }

    /** Signatures for token mismatches (extends sanity checks). */
    if ($this->Configuration['bobuam']['sanity_check'] === 'yes') {
        $Failed = false;
        if (isset($TokenChrome, $this->Tokens['Google Chrome'])) {
            $Try = (int)$this->Tokens['Google Chrome'];
            if ($this->trigger($TokenChrome !== $Try, $Masquerade[0] . ' (TMGC)', $Masquerade[1])) {
                $Failed = true;
            }
        }
        if (isset($TokenEdge, $this->Tokens['Microsoft Edge'])) {
            $Try = (int)$this->Tokens['Microsoft Edge'];
            if ($this->trigger($TokenEdge !== $Try, $Masquerade[0] . ' (TMME)', $Masquerade[1])) {
                $Failed = true;
            }
        }
        if ($Failed) {
            $this->enactOptions('Masquerade:', $Options);
        }
    }
};

/** Execute closure. */
$this->CIDRAM['ModuleResCache'][$Module]();
