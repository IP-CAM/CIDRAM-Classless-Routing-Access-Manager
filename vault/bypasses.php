<?php
/**
 * This file is a part of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Default signature bypasses (last modified: 2021.07.29).
 */

/** Prevents execution from outside of CIDRAM. */
if (!defined('CIDRAM')) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Prevents execution from outside of the CheckFactors closure. */
if (!isset($Factors[$FactorIndex])) {
    die('[CIDRAM] This should not be accessed directly.');
}

/** Safety. */
if (!isset($CIDRAM['RunParamResCache'])) {
    $CIDRAM['RunParamResCache'] = [];
}

/**
 * Define object for these rules for later recall (all parameters inherited from CheckFactors).
 *
 * @param array $Factors All CIDR factors of the IP being checked.
 * @param int $FactorIndex The index of the CIDR factor of the triggered rule.
 * @param string $LN The line information generated by CheckFactors.
 * @param string $Tag The triggered rule's section's name (if there's any).
 */
$CIDRAM['RunParamResCache']['bypasses.php'] = function (array $Factors = [], int $FactorIndex = 0, string $LN = '', string $Tag = '') use (&$CIDRAM) {
    /** Skip processing if the bypasses aren't active. */
    if (!isset($CIDRAM['Config']['bypasses'])) {
        return;
    }

    /**
     * OVH rules (determine which directive the signatures should fall under,
     * since in order to do so, it requires additional checks beyond just the
     * range itself; i.e., checking the hostname).
     */
    if ($Tag === 'OVH Systems') {
        /** Fetch hostname. */
        if (empty($CIDRAM['Hostname'])) {
            $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
        }

        /** ADSL hostnames (should fall under "spam" directive, since not a cloud service). */
        if (preg_match('~(?:dsl\.ovh|ovhtelecom)\.fr$~i', $CIDRAM['Hostname'])) {
            /** Return early if "block_spam" is false. */
            if (!$CIDRAM['Config']['signatures']['block_spam']) {
                return;
            }

            $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['L10N']->getString('ReasonMessage_Spam');
            if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
                $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
            }
            $CIDRAM['BlockInfo']['WhyReason'] .= $CIDRAM['L10N']->getString('Short_Spam') . $LN;
            if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
                $CIDRAM['BlockInfo']['Signatures'] .= ', ';
            }
            $CIDRAM['BlockInfo']['Signatures'] .= $Factors[$FactorIndex];
            $CIDRAM['BlockInfo']['SignatureCount']++;

            /** Exit. */
            return;
        }

        /** Return early if "block_cloud" is false. */
        if (!$CIDRAM['Config']['signatures']['block_cloud']) {
            return;
        }

        $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['L10N']->getString('ReasonMessage_Cloud');
        if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
            $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
        }
        $CIDRAM['BlockInfo']['WhyReason'] .= $CIDRAM['L10N']->getString('Short_Cloud') . $LN;
        if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
            $CIDRAM['BlockInfo']['Signatures'] .= ', ';
        }
        $CIDRAM['BlockInfo']['Signatures'] .= $Factors[$FactorIndex];
        $CIDRAM['BlockInfo']['SignatureCount']++;

        /** Exit. */
        return;
    }

    /** Skip further processing if the "block_cloud" directive is false, or if no section tag has been defined. */
    if (!$CIDRAM['Config']['signatures']['block_cloud'] || !$Tag) {
        return;
    }

    /** Amazon AWS bypasses. */
    if ($Tag === 'Amazon.com, Inc') {
        /** DuckDuckGo bypass. */
        if (
            $CIDRAM['Request']->inCsv('DuckDuckBot', $CIDRAM['Config']['bypasses']['used']) &&
            preg_match('~duckduck(?:go-favicons-)?bot~', $CIDRAM['BlockInfo']['UALC'])
        ) {
            return 4;
        }

        /** Embedly bypass. */
        if (
            $CIDRAM['Request']->inCsv('Embedly', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'embedly') !== false
        ) {
            return;
        }

        /**
         * Feedspot bypass.
         * See: https://udger.com/resources/ua-list/bot-detail?bot=Feedspotbot
         */
        if (
            $CIDRAM['Request']->inCsv('Feedspot', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UA'], '+https://www.feedspot.com/fs/fetcher') !== false
        ) {
            return;
        }

        /** Pinterest bypass. */
        if (
            $CIDRAM['Request']->inCsv('Pinterest', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'pinterest') !== false
        ) {
            return;
        }

        /** Redditbot bypass. */
        if (
            $CIDRAM['Request']->inCsv('Redditbot', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'redditbot/') !== false
        ) {
            return;
        }
    }

    /** Azure bypasses. */
    if ($Tag === 'Azure') {
        /** Bingbot bypass. */
        if ($CIDRAM['Request']->inCsv('Bingbot', $CIDRAM['Config']['bypasses']['used'])) {
            if (empty($CIDRAM['Hostname'])) {
                $CIDRAM['Hostname'] = $CIDRAM['DNS-Reverse']($CIDRAM['BlockInfo']['IPAddr']);
            }
            if (
                preg_match('~^msnbot-\d+-\d+-\d+-\d+\.search\.msn\.com$~i', $CIDRAM['Hostname']) ||
                preg_match('~(?:msn|bing)bot|bingpreview~', $CIDRAM['BlockInfo']['UALC'])
            ) {
                $CIDRAM['Flag-Bypass-Bingbot-Check'] = true;
                return 4;
            }
        }

        /** DuckDuckGo bypass. */
        if (
            $CIDRAM['Request']->inCsv('DuckDuckBot', $CIDRAM['Config']['bypasses']['used']) &&
            preg_match('~duckduck(?:go-favicons-)?bot~', $CIDRAM['BlockInfo']['UALC'])
        ) {
            return 4;
        }
    }

    /** Oracle bypasses. */
    if ($Tag === 'Oracle Corporation') {
        /** Oracle Data Cloud Crawler (a.k.a., Grapeshot) bypass. */
        if (
            $CIDRAM['Request']->inCsv('Grapeshot', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'grapeshot') !== false
        ) {
            return;
        }
    }

    /** Automattic bypasses. */
    if ($Tag === 'Automattic') {
        /** Feedbot bypass. */
        if (
            $CIDRAM['Request']->inCsv('Feedbot', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'wp.com feedbot/1.0 (+https://wp.com)') !== false
        ) {
            return;
        }

        /** Jetpack bypass. */
        if (
            $CIDRAM['Request']->inCsv('Jetpack', $CIDRAM['Config']['bypasses']['used']) &&
            strpos($CIDRAM['BlockInfo']['UALC'], 'jetpack') !== false
        ) {
            return;
        }
    }

    /** Disqus bypass. */
    if (
        $Tag === 'SoftLayer' &&
        $CIDRAM['Request']->inCsv('Disqus', $CIDRAM['Config']['bypasses']['used']) &&
        strpos($CIDRAM['BlockInfo']['UALC'], 'disqus') !== false
    ) {
        return;
    }

    /** AbuseIPDB webmaster verification bot bypass. */
    if (
        $Tag === 'Digital Ocean, Inc' &&
        $CIDRAM['Request']->inCsv('AbuseIPDB', $CIDRAM['Config']['bypasses']['used']) &&
        $CIDRAM['BlockInfo']['UA'] === 'AbuseIPDB_Bot/1.0'
    ) {
        return;
    }

    $CIDRAM['BlockInfo']['ReasonMessage'] = $CIDRAM['L10N']->getString('ReasonMessage_Cloud');
    if (!empty($CIDRAM['BlockInfo']['WhyReason'])) {
        $CIDRAM['BlockInfo']['WhyReason'] .= ', ';
    }
    $CIDRAM['BlockInfo']['WhyReason'] .= $CIDRAM['L10N']->getString('Short_Cloud') . $LN;
    if (!empty($CIDRAM['BlockInfo']['Signatures'])) {
        $CIDRAM['BlockInfo']['Signatures'] .= ', ';
    }
    $CIDRAM['BlockInfo']['Signatures'] .= $Factors[$FactorIndex];
    $CIDRAM['BlockInfo']['SignatureCount']++;
};

/** Execute object. */
$RunExitCode = $CIDRAM['RunParamResCache']['bypasses.php']($Factors, $FactorIndex, $LN, $Tag);
