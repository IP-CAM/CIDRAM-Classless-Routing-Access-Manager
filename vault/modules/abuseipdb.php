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
 * This file: AbuseIPDB module (last modified: 2024.06.11).
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
    if (empty($this->BlockInfo['IPAddr']) || $this->Configuration['abuseipdb']['lookup_strategy'] === 0) {
        return;
    }

    /**
     * We can't perform lookups without an API key, so we should check for
     * that, too.
     */
    if ($this->Configuration['abuseipdb']['api_key'] === '') {
        return;
    }

    /**
     * Normalised, lower-cased request URI; Used to determine whether the
     * module needs to do anything for the request.
     */
    $LCURI = preg_replace('/\s/', '', strtolower($this->BlockInfo['rURI']));

    /**
     * If the request isn't attempting to access a sensitive page (login,
     * registration page, etc), exit.
     */
    if ($this->Configuration['abuseipdb']['lookup_strategy'] !== 1 && !$this->isSensitive($LCURI)) {
        return;
    }

    /** Check whether the lookup limit has been exceeded. */
    if (!isset($this->CIDRAM['AbuseIPDB-429'])) {
        $this->CIDRAM['AbuseIPDB-429'] = $this->Cache->getEntry('AbuseIPDB-429') ? true : false;
    }

    /**
     * Only execute if not already blocked for some other reason, if the IP is
     * valid, if not from a private or reserved range, and if the lookup limit
     * hasn't already been exceeded (reduces superfluous lookups).
     */
    if (
        $this->CIDRAM['AbuseIPDB-429'] ||
        !$this->honourLookup() ||
        filter_var($this->BlockInfo['IPAddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
    ) {
        return;
    }

    /** Executed if there aren't any cache entries corresponding to the IP of the request. */
    if (
        !isset($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]) ||
        $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']] === false
    ) {
        $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']] = $this->Cache->getEntry('AbuseIPDB-' . $this->BlockInfo['IPAddr']);
        if ($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']] === false) {
            /** Perform AbuseIPDB lookup. */
            $Lookup = $this->Request->request(
                'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode($this->BlockInfo['IPAddr']) . '&maxAgeInDays=' . $this->Configuration['abuseipdb']['max_age_in_days'],
                [],
                $this->Configuration['abuseipdb']['timeout_limit'],
                ['Key: ' . $this->Configuration['abuseipdb']['api_key'], 'Accept: application/json']
            );

            if ($this->Request->MostRecentStatusCode === 429) {
                /** Lookup limit has been exceeded. */
                $this->Cache->setEntry('AbuseIPDB-429', true, $this->Configuration['abuseipdb']['timeout_rl']->getAsSeconds());
                $this->CIDRAM['AbuseIPDB-429'] = true;
                return;
            }

            /** Validate or substitute. */
            $Lookup = strpos($Lookup, '"abuseConfidenceScore":') !== false ? (json_decode($Lookup, true) ?: []) : [];

            /** Generate local AbuseIPDB cache entry. */
            $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']] = $Lookup['data'] ?? [];

            /** Ensure confidence score. */
            if (!isset($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['abuseConfidenceScore'])) {
                $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['abuseConfidenceScore'] = 0;
            }

            /** Ensure total reports. */
            if (!isset($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['totalReports'])) {
                $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['totalReports'] = 0;
            }

            /** Check whether whitelisted. */
            $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['isWhitelisted'] = !empty($Lookup['data']['isWhitelisted']);

            /** Update cache. */
            $this->Cache->setEntry(
                'AbuseIPDB-' . $this->BlockInfo['IPAddr'],
                $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']],
                $this->Configuration['abuseipdb'][(!isset($Lookup['data']) || $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['abuseConfidenceScore'] < 1) ? 'expire_bad' : 'expire_good']->getAsSeconds()
            );
        }
    }

    /** Guard. */
    if (
        !isset($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]) ||
        !is_array($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']])
    ) {
        return;
    }

    /** Block the request if the IP is listed by AbuseIPDB. */
    if ($this->trigger(
        (
            !(
                (isset($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['usageType']) && $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['usageType'] === 'Search Engine Spider') ||
                $this->hasProfile(['Search Engine', 'Search Engine Spider', 'Search engine']) ||
                (isset($this->BlockInfo['Verified']) && $this->BlockInfo['Verified'] !== '')
            ) &&
            $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['isWhitelisted'] === false &&
            $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['abuseConfidenceScore'] >= $this->Configuration['abuseipdb']['minimum_confidence_score'] &&
            $this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['totalReports'] >= $this->Configuration['abuseipdb']['minimum_total_reports']
        ),
        'AbuseIPDB Lookup',
        $this->L10N->getString('ReasonMessage_Generic') . '<br />' . sprintf($this->L10N->getString('request_removal'), 'https://www.abuseipdb.com/check/' . $this->BlockInfo['IPAddr'])
    )) {
        /** Fetch options. */
        $this->enactOptions('', array_flip(explode("\n", $this->Configuration['abuseipdb']['options'])));
    }

    /** Build profiles. */
    if (
        $this->Configuration['abuseipdb']['build_profiles_from_usage_type'] &&
        !empty($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['usageType'])
    ) {
        $this->addProfileEntry($this->CIDRAM['AbuseIPDB-' . $this->BlockInfo['IPAddr']]['usageType']);
    }
};

/** Add AbuseIPDB report handler. */
if ($this->Configuration['abuseipdb']['report_back'] && $this->Configuration['abuseipdb']['api_key'] !== '') {
    $this->Reporter->addHandler(function (array $Report, string $DateTime) {
        if ($this->Configuration['abuseipdb']['report_back'] === 2 && $this->BlockInfo['SignatureCount'] < 1) {
            return;
        }
        if (!isset($this->CIDRAM['AbuseIPDB-Recently Reported-' . $Report['IP']])) {
            $this->CIDRAM['AbuseIPDB-Recently Reported-' . $Report['IP']] = $this->Cache->getEntry('AbuseIPDB-Recently Reported-' . $Report['IP']);
        }
        $Categories = [];
        foreach ($Report['Categories'] as $Category) {
            if ($Category > 2 && $Category < 24) {
                $Categories[] = $Category;
            }
        }
        if (!count($Categories)) {
            return;
        }
        $Categories = implode(',', $Categories);
        $Queue = true;
        if ($this->CIDRAM['AbuseIPDB-Recently Reported-' . $Report['IP']] === false) {
            $Status = $this->Request->request('https://api.abuseipdb.com/api/v2/report', [
                'ip' => $Report['IP'],
                'categories' => $Categories,
                'comment' => $Report['Comments'],
                'timestamp' => $DateTime
            ], $this->Configuration['abuseipdb']['timeout_limit'], [
                'Key: ' . $this->Configuration['abuseipdb']['api_key'],
                'Accept: application/json'
            ]);
            $this->Cache->setEntry('AbuseIPDB-Recently Reported-' . $Report['IP'], true, 900);
            $this->CIDRAM['AbuseIPDB-Recently Reported-' . $Report['IP']] = true;
            if (strpos($Status, '"ipAddress":"' . $Report['IP'] . '"') !== false && strpos($Status, '"errors":') === false) {
                if (!isset($this->CIDRAM['Report OK'])) {
                    $this->CIDRAM['Report OK'] = 0;
                }
                $this->CIDRAM['Report OK']++;
                $Queue = false;
            } else {
                if (!isset($this->CIDRAM['Report Failed'])) {
                    $this->CIDRAM['Report Failed'] = 0;
                }
                $this->CIDRAM['Report Failed']++;
            }
        }
        if ($Queue) {
            if (!isset($this->CIDRAM['AbuseIPDB-Report Queue'])) {
                $this->CIDRAM['AbuseIPDB-Report Queue'] = $this->Cache->getEntry('AbuseIPDB-Report Queue');
            }
            if (!is_string($this->CIDRAM['AbuseIPDB-Report Queue'])) {
                $this->CIDRAM['AbuseIPDB-Report Queue'] = '';
            }
            if (substr_count($this->CIDRAM['AbuseIPDB-Report Queue'], '|' . $Report['IP'] . '|') < 10) {
                $this->CIDRAM['AbuseIPDB-Report Queue'] .= $this->Now . '|' . $Report['IP'] . '|' . $Categories . '|' . $Report['Comments'] . '||';
            }
        }
    });
}

/** Execute closure. */
$this->CIDRAM['ModuleResCache'][$Module]();
